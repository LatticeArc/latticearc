//! Key-dependent timing independence tests for actual crypto operations.
//!
//! Verifies that encryption/decryption timing does not depend on the key value
//! (SP 800-175B §4.1). Uses statistical comparison of timing distributions
//! across different key values.
//!
//! Each test measures the same operation with two independently-generated keys
//! and asserts that the median timing ratio stays within 2.0x — a generous bound
//! chosen to tolerate CI runner noise while still catching catastrophic
//! key-dependent branches (which typically show ratios of 5x or more).
//!
//! ## Measurement methodology
//!
//! Naive "measure op1 fully, then op2 fully" produces large first-key bias on
//! CI runners: whichever op is measured first pays for cold caches, CPU
//! frequency ramp-up, and initial codegen, showing 5-7x ratios even for
//! hardware-backed constant-time primitives (AES-NI, fixed SHA-256 loops).
//!
//! To eliminate that bias, each test:
//! 1. Runs a warmup phase (both operations, discarded) to warm caches and
//!    stabilize CPU frequency scaling.
//! 2. Measures operations *interleaved* (op1, op2, op1, op2, …) so cache and
//!    scheduler effects are charged symmetrically to both samples.
//! 3. Compares *medians* rather than means — robust to OS jitter outliers
//!    (interrupts, VM scheduling, GC-style pauses) that dominate the tail on
//!    virtualized CI runners.

#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
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

/// Interleaved timing measurement of two operations with warmup.
///
/// Alternates `op1` and `op2` across iterations so that caches, CPU frequency
/// scaling, and OS scheduler effects are charged symmetrically to both samples.
/// Discards `warmup` iterations before recording to eliminate cold-start bias.
fn measure_interleaved<F1, F2>(
    mut op1: F1,
    mut op2: F2,
    warmup: usize,
    iterations: usize,
) -> (Vec<u64>, Vec<u64>)
where
    F1: FnMut(),
    F2: FnMut(),
{
    for _ in 0..warmup {
        op1();
        op2();
    }

    let mut t1 = Vec::with_capacity(iterations);
    let mut t2 = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let start = Instant::now();
        op1();
        t1.push(start.elapsed().as_nanos() as u64);

        let start = Instant::now();
        op2();
        t2.push(start.elapsed().as_nanos() as u64);
    }
    (t1, t2)
}

/// Median of a timing sample in nanoseconds.
fn median_ns(timings: &[u64]) -> f64 {
    let mut sorted: Vec<u64> = timings.to_vec();
    sorted.sort_unstable();
    let mid = sorted.len() / 2;
    if sorted.len().is_multiple_of(2) {
        (sorted[mid - 1] + sorted[mid]) as f64 / 2.0
    } else {
        sorted[mid] as f64
    }
}

/// Ratio between the two medians (always >= 1.0).
///
/// Returns 1.0 if either median is zero (degenerate case — nothing to compare).
fn median_ratio(t1: &[u64], t2: &[u64]) -> f64 {
    let m1 = median_ns(t1);
    let m2 = median_ns(t2);
    if m1 == 0.0 || m2 == 0.0 {
        return 1.0;
    }
    if m1 > m2 { m1 / m2 } else { m2 / m1 }
}

/// Return `true` when the median ratio is within `max_ratio`.
fn timing_distributions_similar(t1: &[u64], t2: &[u64], max_ratio: f64) -> bool {
    median_ratio(t1, t2) <= max_ratio
}

// Maximum allowed ratio of medians between two timing distributions.
// 2.0x is generous enough to tolerate CI jitter while still catching
// key-dependent branches (which typically show ratios of 5x or more).
const MAX_RATIO: f64 = 2.0;
const WARMUP: usize = 50;
const ITERATIONS: usize = 200;

// ============================================================================
// Test 1 — AES-256-GCM encrypt timing independence
// ============================================================================

#[test]
fn test_aes_gcm_encrypt_timing_independence_succeeds() {
    let plaintext = b"constant plaintext for timing measurement across keys";

    // Two independent keys with distinct bit patterns.
    let key1: Vec<u8> = (0u8..32).collect();
    let key2: Vec<u8> = (128u8..160).collect();

    let (timings1, timings2) = measure_interleaved(
        || {
            let _ = encrypt_aes_gcm_unverified(plaintext, &key1);
        },
        || {
            let _ = encrypt_aes_gcm_unverified(plaintext, &key2);
        },
        WARMUP,
        ITERATIONS,
    );

    let ratio = median_ratio(&timings1, &timings2);
    println!(
        "[aes_gcm_encrypt] key1 median={:.0}ns  key2 median={:.0}ns  ratio={:.3}",
        median_ns(&timings1),
        median_ns(&timings2),
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

    let (timings1, timings2) = measure_interleaved(
        || {
            let _ = decrypt_aes_gcm_unverified(&ct1, &key1);
        },
        || {
            let _ = decrypt_aes_gcm_unverified(&ct2, &key2);
        },
        WARMUP,
        ITERATIONS,
    );

    let ratio = median_ratio(&timings1, &timings2);
    println!(
        "[aes_gcm_decrypt] key1 median={:.0}ns  key2 median={:.0}ns  ratio={:.3}",
        median_ns(&timings1),
        median_ns(&timings2),
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

    let (timings1, timings2) = measure_interleaved(
        || {
            let _ = MlKem::encapsulate(&pk1);
        },
        || {
            let _ = MlKem::encapsulate(&pk2);
        },
        WARMUP,
        ITERATIONS,
    );

    let ratio = median_ratio(&timings1, &timings2);
    println!(
        "[ml_kem_encapsulate] pk1 median={:.0}ns  pk2 median={:.0}ns  ratio={:.3}",
        median_ns(&timings1),
        median_ns(&timings2),
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

    let (timings1, timings2) = measure_interleaved(
        || {
            let _ = hkdf(&ikm1, Some(salt), Some(info), output_len);
        },
        || {
            let _ = hkdf(&ikm2, Some(salt), Some(info), output_len);
        },
        WARMUP,
        ITERATIONS,
    );

    let ratio = median_ratio(&timings1, &timings2);
    println!(
        "[hkdf_derive] ikm1 median={:.0}ns  ikm2 median={:.0}ns  ratio={:.3}",
        median_ns(&timings1),
        median_ns(&timings2),
        ratio
    );

    assert!(
        timing_distributions_similar(&timings1, &timings2, MAX_RATIO),
        "HKDF derive timing varies too much between IKMs: ratio={:.3} (max={:.1})",
        ratio,
        MAX_RATIO
    );
}
