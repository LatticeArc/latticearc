//! Key-dependent timing independence tests for actual crypto operations.
//!
//! Verifies that encryption/decryption timing does not depend on the key value
//! (SP 800-175B §4.1). Uses statistical comparison of timing distributions
//! across different key values.
//!
//! Each test measures the same operation with two independently-generated keys
//! and asserts that the mean timing ratio stays within 2.0x — a generous bound
//! chosen to tolerate CI runner noise while still catching catastrophic
//! key-dependent branches (which would show ratios of 5x or more).

#![allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_lossless,
    clippy::cast_precision_loss,
    clippy::print_stdout
)]

use std::time::Instant;

use latticearc::primitives::kdf::hkdf::hkdf;
use latticearc::primitives::kem::ml_kem::{MlKem, MlKemSecurityLevel};
use latticearc::unified_api::{decrypt_aes_gcm_unverified, encrypt_aes_gcm_unverified};

// ============================================================================
// Helpers
// ============================================================================

/// Measure operation timing over N iterations; return durations in nanoseconds.
fn measure_timing<F: FnMut()>(mut op: F, iterations: usize) -> Vec<u64> {
    let mut timings = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let start = Instant::now();
        op();
        timings.push(start.elapsed().as_nanos() as u64);
    }
    timings
}

/// Return `true` when the ratio of means is within `max_ratio`.
///
/// Returns `true` if either mean is zero (degenerate case — nothing to compare).
fn timing_distributions_similar(t1: &[u64], t2: &[u64], max_ratio: f64) -> bool {
    let mean1: f64 = t1.iter().sum::<u64>() as f64 / t1.len() as f64;
    let mean2: f64 = t2.iter().sum::<u64>() as f64 / t2.len() as f64;
    if mean1 == 0.0 || mean2 == 0.0 {
        return true;
    }
    let ratio = if mean1 > mean2 { mean1 / mean2 } else { mean2 / mean1 };
    ratio <= max_ratio
}

/// Compute mean of a timing sample for display purposes.
fn mean_ns(timings: &[u64]) -> f64 {
    timings.iter().sum::<u64>() as f64 / timings.len() as f64
}

/// Compute the ratio between two means (always >= 1.0).
fn mean_ratio(t1: &[u64], t2: &[u64]) -> f64 {
    let m1 = mean_ns(t1);
    let m2 = mean_ns(t2);
    if m1 == 0.0 || m2 == 0.0 {
        return 1.0;
    }
    if m1 > m2 { m1 / m2 } else { m2 / m1 }
}

// Maximum allowed ratio of means between two timing distributions.
// 2.0x is generous enough to tolerate CI jitter; real key-dependent branches
// typically show ratios of 5x or more.
const MAX_RATIO: f64 = 2.0;
const ITERATIONS: usize = 100;

// ============================================================================
// Test 1 — AES-256-GCM encrypt timing independence
// ============================================================================

#[test]
fn test_aes_gcm_encrypt_timing_independence_succeeds() {
    let plaintext = b"constant plaintext for timing measurement across keys";

    // Two independent keys with distinct bit patterns.
    let key1: Vec<u8> = (0u8..32).collect();
    let key2: Vec<u8> = (128u8..160).collect();

    let timings1 = measure_timing(
        || {
            let _ = encrypt_aes_gcm_unverified(plaintext, &key1);
        },
        ITERATIONS,
    );

    let timings2 = measure_timing(
        || {
            let _ = encrypt_aes_gcm_unverified(plaintext, &key2);
        },
        ITERATIONS,
    );

    let ratio = mean_ratio(&timings1, &timings2);
    println!(
        "[aes_gcm_encrypt] key1 mean={:.0}ns  key2 mean={:.0}ns  ratio={:.3}",
        mean_ns(&timings1),
        mean_ns(&timings2),
        ratio
    );

    assert!(
        timing_distributions_similar(&timings1, &timings2, MAX_RATIO),
        "AES-256-GCM encrypt timing varies too much between keys: ratio={:.3} (max={:.1})",
        ratio,
        MAX_RATIO
    );
}

// ============================================================================
// Test 2 — AES-256-GCM decrypt timing independence
// ============================================================================

#[test]
fn test_aes_gcm_decrypt_timing_independence_succeeds() {
    let plaintext = b"constant plaintext for timing measurement across keys";

    let key1: Vec<u8> = (0u8..32).collect();
    let key2: Vec<u8> = (128u8..160).collect();

    // Produce one valid ciphertext per key so that decryption succeeds (and
    // therefore exercises the full MAC verification path).
    let ct1 = encrypt_aes_gcm_unverified(plaintext, &key1).expect("encrypt with key1 must succeed");
    let ct2 = encrypt_aes_gcm_unverified(plaintext, &key2).expect("encrypt with key2 must succeed");

    let timings1 = measure_timing(
        || {
            let _ = decrypt_aes_gcm_unverified(&ct1, &key1);
        },
        ITERATIONS,
    );

    let timings2 = measure_timing(
        || {
            let _ = decrypt_aes_gcm_unverified(&ct2, &key2);
        },
        ITERATIONS,
    );

    let ratio = mean_ratio(&timings1, &timings2);
    println!(
        "[aes_gcm_decrypt] key1 mean={:.0}ns  key2 mean={:.0}ns  ratio={:.3}",
        mean_ns(&timings1),
        mean_ns(&timings2),
        ratio
    );

    assert!(
        timing_distributions_similar(&timings1, &timings2, MAX_RATIO),
        "AES-256-GCM decrypt timing varies too much between keys: ratio={:.3} (max={:.1})",
        ratio,
        MAX_RATIO
    );
}

// ============================================================================
// Test 3 — ML-KEM encapsulate timing independence
// ============================================================================

#[test]
fn test_ml_kem_encapsulate_timing_independence_succeeds() {
    // Generate two independent ML-KEM-768 keypairs.
    let (pk1, _sk1) =
        MlKem::generate_keypair(MlKemSecurityLevel::MlKem768).expect("keygen pk1 must succeed");
    let (pk2, _sk2) =
        MlKem::generate_keypair(MlKemSecurityLevel::MlKem768).expect("keygen pk2 must succeed");

    let timings1 = measure_timing(
        || {
            let _ = MlKem::encapsulate(&pk1);
        },
        ITERATIONS,
    );

    let timings2 = measure_timing(
        || {
            let _ = MlKem::encapsulate(&pk2);
        },
        ITERATIONS,
    );

    let ratio = mean_ratio(&timings1, &timings2);
    println!(
        "[ml_kem_encapsulate] pk1 mean={:.0}ns  pk2 mean={:.0}ns  ratio={:.3}",
        mean_ns(&timings1),
        mean_ns(&timings2),
        ratio
    );

    assert!(
        timing_distributions_similar(&timings1, &timings2, MAX_RATIO),
        "ML-KEM encapsulate timing varies too much between keys: ratio={:.3} (max={:.1})",
        ratio,
        MAX_RATIO
    );
}

// ============================================================================
// Test 4 — HKDF derive timing independence
// ============================================================================

#[test]
fn test_hkdf_derive_timing_independence_succeeds() {
    // Two input keying materials with different bit patterns.
    let ikm1: Vec<u8> = (0u8..32).collect();
    let ikm2: Vec<u8> = (128u8..160).collect();
    let salt = b"fixed-salt-for-timing-test";
    let info = b"timing-independence-info";
    let output_len = 32_usize;

    let timings1 = measure_timing(
        || {
            let _ = hkdf(&ikm1, Some(salt), Some(info), output_len);
        },
        ITERATIONS,
    );

    let timings2 = measure_timing(
        || {
            let _ = hkdf(&ikm2, Some(salt), Some(info), output_len);
        },
        ITERATIONS,
    );

    let ratio = mean_ratio(&timings1, &timings2);
    println!(
        "[hkdf_derive] ikm1 mean={:.0}ns  ikm2 mean={:.0}ns  ratio={:.3}",
        mean_ns(&timings1),
        mean_ns(&timings2),
        ratio
    );

    assert!(
        timing_distributions_similar(&timings1, &timings2, MAX_RATIO),
        "HKDF derive timing varies too much between IKMs: ratio={:.3} (max={:.1})",
        ratio,
        MAX_RATIO
    );
}
