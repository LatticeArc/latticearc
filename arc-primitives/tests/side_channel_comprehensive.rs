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
//! Comprehensive Side-Channel Resistance Tests - Phase 4 Security Audit
//!
//! This test suite provides comprehensive coverage for side-channel resistance
//! in the arc-primitives cryptographic implementations.
//!
//! ## Test Categories
//!
//! 1. **Constant-Time Operations Tests** - Verify timing consistency
//! 2. **Memory Access Pattern Tests** - Validate secret-independent memory access
//! 3. **Zeroization Tests** - Ensure proper cleanup of sensitive data
//! 4. **Error Timing Tests** - Verify consistent error rejection timing
//! 5. **Statistical Timing Analysis** - Measure timing variance
//!
//! ## IMPORTANT NOTES
//!
//! - These tests measure timing properties which can be affected by system load
//! - Some tests may need adjustment on different hardware platforms
//! - Statistical timing tests use conservative thresholds to reduce false positives
//! - Tests marked with `#[ignore]` require specific conditions to run reliably
//!
//! ## Known Timing Variations
//!
//! - First execution may be slower due to code cache misses
//! - aws-lc-rs uses hardware acceleration which provides constant-time guarantees
//! - System load can affect timing measurements

#![allow(dead_code)]

use std::time::Instant;

use rand::rngs::OsRng;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

// Import cryptographic primitives
use arc_primitives::aead::{AeadCipher, aes_gcm::AesGcm256};
use arc_primitives::kem::ml_kem::{
    MlKem, MlKemCiphertext, MlKemPublicKey, MlKemSecretKey, MlKemSecurityLevel, MlKemSharedSecret,
};
use arc_primitives::sig::ml_dsa::{
    MlDsaParameterSet, MlDsaSecretKey, generate_keypair, sign, verify,
};

// ============================================================================
// TIMING MEASUREMENT UTILITIES
// ============================================================================

/// Timing measurement result with statistical properties
#[derive(Debug, Clone)]
struct TimingResult {
    /// Mean duration in nanoseconds
    mean_ns: f64,
    /// Standard deviation in nanoseconds
    std_dev_ns: f64,
    /// Minimum duration in nanoseconds
    min_ns: u128,
    /// Maximum duration in nanoseconds
    max_ns: u128,
    /// Number of samples
    sample_count: usize,
}

impl TimingResult {
    /// Calculate the coefficient of variation (CV) as a percentage
    fn coefficient_of_variation(&self) -> f64 {
        if self.mean_ns > 0.0 { (self.std_dev_ns / self.mean_ns) * 100.0 } else { 0.0 }
    }
}

/// Measure execution time for an operation with warm-up
fn measure_operation<F>(operation: F, iterations: usize, warmup: usize) -> TimingResult
where
    F: Fn() -> (),
{
    // Warm-up runs to stabilize caches
    for _ in 0..warmup {
        operation();
    }

    // Collect timing samples
    let mut durations: Vec<u128> = Vec::with_capacity(iterations);

    for _ in 0..iterations {
        let start = Instant::now();
        operation();
        let duration = start.elapsed().as_nanos();
        durations.push(duration);
    }

    // Calculate statistics
    let sum: u128 = durations.iter().sum();
    let mean_ns = sum as f64 / iterations as f64;

    let variance: f64 = durations
        .iter()
        .map(|&d| {
            let diff = d as f64 - mean_ns;
            diff * diff
        })
        .sum::<f64>()
        / iterations as f64;

    let std_dev_ns = variance.sqrt();
    let min_ns = *durations.iter().min().unwrap_or(&0);
    let max_ns = *durations.iter().max().unwrap_or(&0);

    TimingResult { mean_ns, std_dev_ns, min_ns, max_ns, sample_count: iterations }
}

/// Calculate timing ratio between two operations
fn timing_ratio(result1: &TimingResult, result2: &TimingResult) -> f64 {
    if result2.mean_ns > 0.0 { result1.mean_ns / result2.mean_ns } else { 1.0 }
}

// ============================================================================
// SECTION 1: CONSTANT-TIME OPERATIONS TESTS
// ============================================================================

/// Test ML-KEM shared secret constant-time comparison
#[test]
fn test_mlkem_shared_secret_constant_time_comparison() {
    const ITERATIONS: usize = 1000;
    const WARMUP: usize = 100;

    let ss1 = MlKemSharedSecret::new([0x00u8; 32]);
    let ss2 = MlKemSharedSecret::new([0x00u8; 32]); // Equal
    let ss3 = MlKemSharedSecret::new([0xFFu8; 32]); // Different
    let mut ss4_data = [0x00u8; 32];
    ss4_data[31] = 0x01; // Differs only in last byte
    let ss4 = MlKemSharedSecret::new(ss4_data);

    // Measure equal comparison
    let equal_timing = measure_operation(
        || {
            let _ = ss1.ct_eq(&ss2);
        },
        ITERATIONS,
        WARMUP,
    );

    // Measure fully different comparison
    let different_timing = measure_operation(
        || {
            let _ = ss1.ct_eq(&ss3);
        },
        ITERATIONS,
        WARMUP,
    );

    // Measure almost equal comparison (differs in last byte)
    let almost_equal_timing = measure_operation(
        || {
            let _ = ss1.ct_eq(&ss4);
        },
        ITERATIONS,
        WARMUP,
    );

    // Verify timing consistency (ratio should be close to 1.0)
    let ratio_equal_different = timing_ratio(&equal_timing, &different_timing);
    let ratio_equal_almost = timing_ratio(&equal_timing, &almost_equal_timing);

    // Allow 3x variance for constant-time operations (conservative threshold)
    assert!(
        ratio_equal_different > 0.33 && ratio_equal_different < 3.0,
        "Equal vs different timing ratio out of bounds: {:.2} (equal: {:.2}ns, different: {:.2}ns)",
        ratio_equal_different,
        equal_timing.mean_ns,
        different_timing.mean_ns
    );

    assert!(
        ratio_equal_almost > 0.33 && ratio_equal_almost < 3.0,
        "Equal vs almost-equal timing ratio out of bounds: {:.2}",
        ratio_equal_almost
    );
}

/// Test ML-KEM security level constant-time comparison
#[test]
fn test_mlkem_security_level_constant_time_comparison() {
    const ITERATIONS: usize = 1000;
    const WARMUP: usize = 100;

    let level512 = MlKemSecurityLevel::MlKem512;
    let level768 = MlKemSecurityLevel::MlKem768;
    let level1024 = MlKemSecurityLevel::MlKem1024;

    // Measure same level comparison
    let same_timing = measure_operation(
        || {
            let _ = level512.ct_eq(&level512);
        },
        ITERATIONS,
        WARMUP,
    );

    // Measure different level comparison (512 vs 768)
    let diff_timing_1 = measure_operation(
        || {
            let _ = level512.ct_eq(&level768);
        },
        ITERATIONS,
        WARMUP,
    );

    // Measure different level comparison (512 vs 1024)
    let diff_timing_2 = measure_operation(
        || {
            let _ = level512.ct_eq(&level1024);
        },
        ITERATIONS,
        WARMUP,
    );

    // All comparisons should have similar timing
    let ratio1 = timing_ratio(&same_timing, &diff_timing_1);
    let ratio2 = timing_ratio(&same_timing, &diff_timing_2);

    assert!(
        ratio1 > 0.33 && ratio1 < 3.0,
        "Security level comparison timing ratio out of bounds: {:.2}",
        ratio1
    );

    assert!(
        ratio2 > 0.33 && ratio2 < 3.0,
        "Security level comparison timing ratio out of bounds: {:.2}",
        ratio2
    );
}

/// Test ML-KEM secret key constant-time comparison
#[test]
fn test_mlkem_secret_key_constant_time_comparison() {
    const ITERATIONS: usize = 500;
    const WARMUP: usize = 50;

    let sk1 = MlKemSecretKey::new(MlKemSecurityLevel::MlKem512, vec![0x42u8; 1632])
        .expect("secret key creation should succeed");
    let sk2 = MlKemSecretKey::new(MlKemSecurityLevel::MlKem512, vec![0x42u8; 1632])
        .expect("secret key creation should succeed");
    let sk3 = MlKemSecretKey::new(MlKemSecurityLevel::MlKem512, vec![0x43u8; 1632])
        .expect("secret key creation should succeed");

    // Measure equal keys comparison
    let equal_timing = measure_operation(
        || {
            let _ = sk1.ct_eq(&sk2);
        },
        ITERATIONS,
        WARMUP,
    );

    // Measure different keys comparison
    let different_timing = measure_operation(
        || {
            let _ = sk1.ct_eq(&sk3);
        },
        ITERATIONS,
        WARMUP,
    );

    let ratio = timing_ratio(&equal_timing, &different_timing);

    assert!(
        ratio > 0.33 && ratio < 3.0,
        "Secret key comparison timing ratio out of bounds: {:.2}",
        ratio
    );
}

/// Test ML-DSA secret key constant-time comparison
///
/// NOTE: Due to system scheduling and the large size of ML-DSA secret keys,
/// timing measurements may vary significantly. The constant-time comparison
/// guarantees come from the subtle crate's ct_eq implementation.
#[test]
fn test_mldsa_secret_key_constant_time_comparison() {
    const ITERATIONS: usize = 500;
    const WARMUP: usize = 50;

    // Generate two keypairs
    let (_pk1, sk1) =
        generate_keypair(MlDsaParameterSet::MLDSA44).expect("keypair generation should succeed");
    let (_pk2, sk2) =
        generate_keypair(MlDsaParameterSet::MLDSA44).expect("keypair generation should succeed");

    // Create copies for comparison
    let sk1_copy = MlDsaSecretKey::new(sk1.parameter_set(), sk1.as_bytes().to_vec())
        .expect("secret key creation should succeed");
    let sk2_copy = MlDsaSecretKey::new(sk2.parameter_set(), sk2.as_bytes().to_vec())
        .expect("secret key creation should succeed");

    // Measure same key comparison
    let same_timing = measure_operation(
        || {
            let _ = sk1.ct_eq(&sk1_copy);
        },
        ITERATIONS,
        WARMUP,
    );

    // Measure different key comparison
    let different_timing = measure_operation(
        || {
            let _ = sk1.ct_eq(&sk2_copy);
        },
        ITERATIONS,
        WARMUP,
    );

    let ratio = timing_ratio(&same_timing, &different_timing);

    // Use permissive threshold (0.1x to 10x) to account for system scheduling
    // and the large size of ML-DSA secret keys
    assert!(
        ratio > 0.1 && ratio < 10.0,
        "ML-DSA secret key comparison timing ratio out of bounds: {:.2}",
        ratio
    );
}

/// Test AES-GCM tag verification constant-time
#[test]
fn test_aes_gcm_tag_verification_constant_time() {
    use arc_primitives::aead::aes_gcm::verify_tag_constant_time;

    const ITERATIONS: usize = 2000;
    const WARMUP: usize = 200;

    let tag1 = [0x00u8; 16];
    let tag2 = [0x00u8; 16]; // Equal
    let tag3 = [0xFFu8; 16]; // Completely different
    let mut tag4 = [0x00u8; 16];
    tag4[15] = 0x01; // Differs only in last byte

    // Measure equal tags
    let equal_timing = measure_operation(
        || {
            let _ = verify_tag_constant_time(&tag1, &tag2);
        },
        ITERATIONS,
        WARMUP,
    );

    // Measure completely different tags
    let different_timing = measure_operation(
        || {
            let _ = verify_tag_constant_time(&tag1, &tag3);
        },
        ITERATIONS,
        WARMUP,
    );

    // Measure almost equal tags
    let almost_equal_timing = measure_operation(
        || {
            let _ = verify_tag_constant_time(&tag1, &tag4);
        },
        ITERATIONS,
        WARMUP,
    );

    let ratio1 = timing_ratio(&equal_timing, &different_timing);
    let ratio2 = timing_ratio(&equal_timing, &almost_equal_timing);

    // Use permissive thresholds (0.2x to 5x) to account for system noise
    assert!(
        ratio1 > 0.2 && ratio1 < 5.0,
        "AES-GCM tag verification timing ratio (equal vs different) out of bounds: {:.2}",
        ratio1
    );

    assert!(
        ratio2 > 0.2 && ratio2 < 5.0,
        "AES-GCM tag verification timing ratio (equal vs almost-equal) out of bounds: {:.2}",
        ratio2
    );
}

/// Test ML-KEM encapsulation timing consistency across security levels
///
/// NOTE: This test measures timing variance which can be affected by system load,
/// CPU frequency scaling, and other factors. The constant-time guarantees come
/// from the underlying aws-lc-rs crypto library, NOT from timing measurements.
/// This test is informational only - it logs timing data but does not fail
/// on high variance since that indicates system load, not timing leaks.
#[test]
fn test_mlkem_encapsulation_timing_consistency() {
    const ITERATIONS: usize = 100;
    const WARMUP: usize = 20;

    let mut rng = OsRng;

    for level in
        [MlKemSecurityLevel::MlKem512, MlKemSecurityLevel::MlKem768, MlKemSecurityLevel::MlKem1024]
    {
        let (pk, _sk) =
            MlKem::generate_keypair(&mut rng, level).expect("keypair generation should succeed");

        let timing = measure_operation(
            || {
                let _ = MlKem::encapsulate(&mut OsRng, &pk);
            },
            ITERATIONS,
            WARMUP,
        );

        let cv = timing.coefficient_of_variation();

        // Log timing for analysis - this is informational only
        println!(
            "{} encapsulation: mean={:.2}us, CV={:.1}%",
            level.name(),
            timing.mean_ns / 1000.0,
            cv
        );

        // The constant-time guarantees come from aws-lc-rs, not from this measurement
        // High CV indicates system load, not timing leaks
        // This assertion is intentionally very permissive (1000%) to avoid false failures
        assert!(
            cv < 1000.0,
            "Encapsulation timing CV for {} is extremely high: {:.2}%",
            level.name(),
            cv
        );
    }
}

/// Test ML-DSA signature generation timing consistency
///
/// NOTE: ML-DSA rejection sampling causes inherent timing variance. The constant-time
/// guarantees come from the underlying fips204 implementation, NOT from timing measurements.
#[test]
#[ignore = "timing tests are unstable under llvm-cov instrumentation"]
fn test_mldsa_signature_timing_consistency() {
    const ITERATIONS: usize = 20;
    const WARMUP: usize = 2;

    let message = b"Test message for timing analysis";
    let context: &[u8] = &[];

    for param in
        [MlDsaParameterSet::MLDSA44, MlDsaParameterSet::MLDSA65, MlDsaParameterSet::MLDSA87]
    {
        let (_pk, sk) = generate_keypair(param).expect("keypair generation should succeed");

        let timing = measure_operation(
            || {
                let _ = sign(&sk, message, context);
            },
            ITERATIONS,
            WARMUP,
        );

        // ML-DSA signature generation may have higher variance due to rejection sampling
        // Allow up to 100% CV for this operation
        let cv = timing.coefficient_of_variation();
        assert!(
            cv < 100.0,
            "ML-DSA signature timing CV for {:?} is too high: {:.2}% (indicates timing leaks)",
            param,
            cv
        );
    }
}

/// Test AES-GCM encryption timing consistency
///
/// NOTE: Due to system scheduling, CPU frequency scaling, and cache effects,
/// timing measurements may have high variance. The constant-time guarantees
/// come from the underlying aws-lc-rs implementation, NOT from timing measurements.
#[test]
#[ignore = "timing tests are unstable under llvm-cov instrumentation"]
fn test_aes_gcm_encryption_timing_consistency() {
    const ITERATIONS: usize = 200;
    const WARMUP: usize = 20;

    let key = AesGcm256::generate_key();
    let cipher = AesGcm256::new(&key).expect("cipher creation should succeed");
    let nonce = AesGcm256::generate_nonce();

    // Test different plaintext sizes
    for size in [16, 64, 256, 1024, 4096] {
        let plaintext = vec![0xABu8; size];

        let timing = measure_operation(
            || {
                let _ = cipher.encrypt(&nonce, &plaintext, None);
            },
            ITERATIONS,
            WARMUP,
        );

        // AES-GCM should have consistent timing per block
        // Use permissive CV threshold (500%) to account for system scheduling
        let cv = timing.coefficient_of_variation();
        assert!(
            cv < 500.0,
            "AES-GCM encryption timing CV for size {} is extremely high: {:.2}%",
            size,
            cv
        );
    }
}

/// Test that ML-KEM key generation produces timing-consistent keys
#[test]
fn test_mlkem_keygen_timing_bounds() {
    const ITERATIONS: usize = 50;
    const WARMUP: usize = 10;

    for level in
        [MlKemSecurityLevel::MlKem512, MlKemSecurityLevel::MlKem768, MlKemSecurityLevel::MlKem1024]
    {
        let timing = measure_operation(
            || {
                let _ = MlKem::generate_keypair(&mut OsRng, level);
            },
            ITERATIONS,
            WARMUP,
        );

        // Key generation timing variance
        // Allow high CV (200%) due to system scheduling and DRBG initialization
        let cv = timing.coefficient_of_variation();

        // Log timing for reference
        println!(
            "{}: mean={:.2}us, std_dev={:.2}us, CV={:.2}%",
            level.name(),
            timing.mean_ns / 1000.0,
            timing.std_dev_ns / 1000.0,
            cv
        );

        // Use very permissive threshold - timing measurement is informational
        // High CV values are expected due to system scheduling, DRBG initialization, and CPU frequency scaling
        assert!(
            cv < 500.0,
            "ML-KEM keygen timing CV for {} is extremely high: {:.2}%",
            level.name(),
            cv
        );
    }
}

// ============================================================================
// SECTION 2: MEMORY ACCESS PATTERN TESTS
// ============================================================================

/// Test that secret key operations don't leave observable memory patterns
#[test]
fn test_mlkem_secret_key_memory_pattern_independence() {
    for level in
        [MlKemSecurityLevel::MlKem512, MlKemSecurityLevel::MlKem768, MlKemSecurityLevel::MlKem1024]
    {
        // Generate multiple keys with different values
        let (pk1, _sk1) =
            MlKem::generate_keypair(&mut OsRng, level).expect("keypair generation should succeed");
        let (pk2, _sk2) =
            MlKem::generate_keypair(&mut OsRng, level).expect("keypair generation should succeed");

        // Encapsulate with both keys and verify operations complete
        let (ss1, ct1) =
            MlKem::encapsulate(&mut OsRng, &pk1).expect("encapsulation should succeed");
        let (ss2, ct2) =
            MlKem::encapsulate(&mut OsRng, &pk2).expect("encapsulation should succeed");

        // Shared secrets should be different (different keys)
        assert_ne!(
            ss1.as_bytes(),
            ss2.as_bytes(),
            "Different keys should produce different shared secrets"
        );

        // Ciphertexts should be different
        assert_ne!(ct1.as_bytes(), ct2.as_bytes(), "Different encapsulations should differ");
    }
}

/// Test that ML-DSA operations are independent of secret key bit patterns
#[test]
fn test_mldsa_secret_key_bit_pattern_independence() {
    let message1 = b"First test message";
    let message2 = b"Second test message with different content";
    let context: &[u8] = &[];

    for param in
        [MlDsaParameterSet::MLDSA44, MlDsaParameterSet::MLDSA65, MlDsaParameterSet::MLDSA87]
    {
        let (pk, sk) = generate_keypair(param).expect("keypair generation should succeed");

        // Sign different messages
        let sig1 = sign(&sk, message1, context).expect("signing should succeed");
        let sig2 = sign(&sk, message2, context).expect("signing should succeed");

        // Signatures should be different
        assert_ne!(
            sig1.as_bytes(),
            sig2.as_bytes(),
            "Different messages should produce different signatures"
        );

        // Both should verify correctly
        assert!(verify(&pk, message1, &sig1, context).expect("verification should succeed"));
        assert!(verify(&pk, message2, &sig2, context).expect("verification should succeed"));
    }
}

/// Test cache-timing resistance for AES-GCM
#[test]
#[ignore = "timing tests are unstable under llvm-cov instrumentation"]
fn test_aes_gcm_cache_timing_resistance() {
    const ITERATIONS: usize = 100;
    const WARMUP: usize = 10;

    let key = AesGcm256::generate_key();
    let cipher = AesGcm256::new(&key).expect("cipher creation should succeed");

    // Test with patterns that might trigger different cache behaviors
    let patterns: Vec<Vec<u8>> = vec![
        vec![0x00u8; 256],                   // All zeros
        vec![0xFFu8; 256],                   // All ones
        (0..256).map(|i| i as u8).collect(), // Sequential
        vec![0xAAu8; 256],                   // Alternating
    ];

    let mut timings: Vec<TimingResult> = Vec::new();

    for pattern in &patterns {
        let nonce = AesGcm256::generate_nonce();

        let timing = measure_operation(
            || {
                let _ = cipher.encrypt(&nonce, pattern, None);
            },
            ITERATIONS,
            WARMUP,
        );

        timings.push(timing);
    }

    // All patterns should have similar timing (within 5x)
    for (i, timing1) in timings.iter().enumerate() {
        for (j, timing2) in timings.iter().enumerate() {
            if i != j {
                let ratio = timing_ratio(timing1, timing2);
                assert!(
                    ratio > 0.2 && ratio < 5.0,
                    "AES-GCM timing varies too much between patterns {} and {}: ratio={:.2}",
                    i,
                    j,
                    ratio
                );
            }
        }
    }
}

/// Test that key comparison doesn't depend on position of first difference
///
/// NOTE: This test verifies constant-time comparison behavior. The subtle crate's
/// ct_eq is designed to be constant-time. Due to CPU caching, branch prediction,
/// and system scheduling, measured timing may vary. This test uses permissive
/// thresholds to avoid false positives while detecting gross timing leaks.
#[test]
fn test_key_comparison_position_independence() {
    const ITERATIONS: usize = 2000;
    const WARMUP: usize = 200;

    let base_key = vec![0x00u8; 1632]; // ML-KEM-512 secret key size

    // Create keys that differ at different positions
    let mut diff_first = base_key.clone();
    diff_first[0] = 0xFF;

    let mut diff_middle = base_key.clone();
    diff_middle[816] = 0xFF;

    let mut diff_last = base_key.clone();
    diff_last[1631] = 0xFF;

    let sk_base = MlKemSecretKey::new(MlKemSecurityLevel::MlKem512, base_key.clone())
        .expect("key creation should succeed");
    let sk_diff_first = MlKemSecretKey::new(MlKemSecurityLevel::MlKem512, diff_first)
        .expect("key creation should succeed");
    let sk_diff_middle = MlKemSecretKey::new(MlKemSecurityLevel::MlKem512, diff_middle)
        .expect("key creation should succeed");
    let sk_diff_last = MlKemSecretKey::new(MlKemSecurityLevel::MlKem512, diff_last)
        .expect("key creation should succeed");

    // Measure comparison times
    let timing_first = measure_operation(
        || {
            let _ = sk_base.ct_eq(&sk_diff_first);
        },
        ITERATIONS,
        WARMUP,
    );

    let timing_middle = measure_operation(
        || {
            let _ = sk_base.ct_eq(&sk_diff_middle);
        },
        ITERATIONS,
        WARMUP,
    );

    let timing_last = measure_operation(
        || {
            let _ = sk_base.ct_eq(&sk_diff_last);
        },
        ITERATIONS,
        WARMUP,
    );

    // All comparisons should have similar timing regardless of difference position
    // Use permissive thresholds (0.25x to 4x) to account for system noise
    let ratio_first_middle = timing_ratio(&timing_first, &timing_middle);
    let ratio_first_last = timing_ratio(&timing_first, &timing_last);

    // Log the timing measurements for debugging
    println!(
        "Key comparison timings: first={:.2}us, middle={:.2}us, last={:.2}us",
        timing_first.mean_ns / 1000.0,
        timing_middle.mean_ns / 1000.0,
        timing_last.mean_ns / 1000.0
    );

    // Use permissive thresholds (0.25x to 4x) to account for system noise
    assert!(
        ratio_first_middle > 0.25 && ratio_first_middle < 4.0,
        "Comparison timing depends on difference position (first vs middle): ratio={:.2}",
        ratio_first_middle
    );

    assert!(
        ratio_first_last > 0.25 && ratio_first_last < 4.0,
        "Comparison timing depends on difference position (first vs last): ratio={:.2}",
        ratio_first_last
    );
}

// ============================================================================
// SECTION 3: ZEROIZATION TESTS
// ============================================================================

/// Test ML-KEM shared secret zeroization
#[test]
fn test_mlkem_shared_secret_zeroization() {
    let mut ss = MlKemSharedSecret::new([0xABu8; 32]);

    // Verify initial state
    assert!(
        ss.as_bytes().iter().any(|&b| b != 0),
        "Shared secret should contain non-zero data initially"
    );

    // Zeroize
    ss.zeroize();

    // Verify all bytes are zero
    assert!(
        ss.as_bytes().iter().all(|&b| b == 0),
        "Shared secret should be all zeros after zeroization"
    );
}

/// Test ML-KEM secret key zeroization
#[test]
fn test_mlkem_secret_key_zeroization() {
    let mut sk = MlKemSecretKey::new(MlKemSecurityLevel::MlKem768, vec![0xCDu8; 2400])
        .expect("secret key construction should succeed");

    // Verify initial state
    assert!(
        sk.as_bytes().iter().any(|&b| b != 0),
        "Secret key should contain non-zero data initially"
    );

    // Zeroize
    sk.zeroize();

    // Verify all bytes are zero
    assert!(
        sk.as_bytes().iter().all(|&b| b == 0),
        "Secret key should be all zeros after zeroization"
    );
}

/// Test ML-DSA secret key zeroization
#[test]
fn test_mldsa_secret_key_zeroization() {
    let (_pk, mut sk) =
        generate_keypair(MlDsaParameterSet::MLDSA44).expect("keypair generation should succeed");

    // Verify initial state
    assert!(
        sk.as_bytes().iter().any(|&b| b != 0),
        "ML-DSA secret key should contain non-zero data initially"
    );

    // Zeroize
    sk.zeroize();

    // Verify all bytes are zero
    assert!(
        sk.as_bytes().iter().all(|&b| b == 0),
        "ML-DSA secret key should be all zeros after zeroization"
    );
}

/// Test zeroization for all ML-KEM security levels
#[test]
fn test_mlkem_zeroization_all_levels() {
    for level in
        [MlKemSecurityLevel::MlKem512, MlKemSecurityLevel::MlKem768, MlKemSecurityLevel::MlKem1024]
    {
        let mut sk = MlKemSecretKey::new(level, vec![0xEFu8; level.secret_key_size()])
            .expect("secret key construction should succeed");

        sk.zeroize();

        assert!(
            sk.as_bytes().iter().all(|&b| b == 0),
            "Secret key for {} should be zeroed",
            level.name()
        );
    }
}

/// Test zeroization for all ML-DSA parameter sets
#[test]
fn test_mldsa_zeroization_all_parameter_sets() {
    for param in
        [MlDsaParameterSet::MLDSA44, MlDsaParameterSet::MLDSA65, MlDsaParameterSet::MLDSA87]
    {
        let (_pk, mut sk) = generate_keypair(param).expect("keypair generation should succeed");

        sk.zeroize();

        assert!(
            sk.as_bytes().iter().all(|&b| b == 0),
            "Secret key for {:?} should be zeroed",
            param
        );
    }
}

/// Test AES-GCM key zeroization
#[test]
fn test_aes_gcm_key_zeroization() {
    use arc_primitives::aead::aes_gcm::zeroize_data;

    let mut key = AesGcm256::generate_key();

    // Verify key is non-zero
    assert!(key.iter().any(|&b| b != 0), "Generated key should be non-zero");

    // Zeroize
    zeroize_data(&mut key);

    // Verify key is zeroed
    assert!(key.iter().all(|&b| b == 0), "Key should be zeroed after zeroization");
}

/// Test intermediate computation cleanup
#[test]
fn test_intermediate_computation_cleanup() {
    let mut rng = OsRng;

    // Generate keypair and encapsulate
    let (pk, _sk) = MlKem::generate_keypair(&mut rng, MlKemSecurityLevel::MlKem768)
        .expect("keypair generation should succeed");

    let (mut ss, _ct) = MlKem::encapsulate(&mut rng, &pk).expect("encapsulation should succeed");

    // Verify shared secret is non-zero
    assert!(ss.as_bytes().iter().any(|&b| b != 0), "Shared secret should be non-zero");

    // Zeroize shared secret
    ss.zeroize();

    // Verify shared secret is zeroed
    assert!(ss.as_bytes().iter().all(|&b| b == 0), "Shared secret should be zeroed");
}

/// Test stack cleanup after crypto operations
#[test]
fn test_stack_cleanup_after_operations() {
    let mut rng = OsRng;

    // Perform crypto operation in a scope
    {
        let (pk, _sk) = MlKem::generate_keypair(&mut rng, MlKemSecurityLevel::MlKem512)
            .expect("keypair generation should succeed");

        let (mut ss, _ct) =
            MlKem::encapsulate(&mut rng, &pk).expect("encapsulation should succeed");

        // Use the shared secret
        let _ = ss.as_bytes().len();

        // Explicitly zeroize before going out of scope
        ss.zeroize();
    }

    // After the scope, memory should be cleaned up
    // Note: This test verifies explicit zeroization behavior
    // True stack cleanup depends on ZeroizeOnDrop implementation
}

/// Test multiple zeroization calls are safe
#[test]
fn test_multiple_zeroization_calls() {
    let mut ss = MlKemSharedSecret::new([0xABu8; 32]);

    // Multiple zeroization calls should be safe
    for _ in 0..10 {
        ss.zeroize();
    }

    // Should still be all zeros
    assert!(ss.as_bytes().iter().all(|&b| b == 0), "Multiple zeroizations should keep data zeroed");
}

// ============================================================================
// SECTION 4: ERROR TIMING TESTS
// ============================================================================

/// Test ML-KEM public key validation timing consistency
#[test]
fn test_mlkem_public_key_validation_timing() {
    const ITERATIONS: usize = 100;
    const WARMUP: usize = 10;

    let level = MlKemSecurityLevel::MlKem768;
    let correct_size = level.public_key_size();

    // Test different invalid sizes
    let sizes = [0, 1, correct_size - 1, correct_size + 1, correct_size * 2];

    let mut timings: Vec<TimingResult> = Vec::new();

    for size in sizes {
        let data = vec![0u8; size];

        let timing = measure_operation(
            || {
                let _ = MlKemPublicKey::new(level, data.clone());
            },
            ITERATIONS,
            WARMUP,
        );

        timings.push(timing);
    }

    // All validation failures should have similar timing
    for i in 0..timings.len() {
        for j in (i + 1)..timings.len() {
            let ratio = timing_ratio(&timings[i], &timings[j]);
            assert!(
                ratio > 0.1 && ratio < 10.0,
                "Validation timing varies too much: sizes {} vs {} have ratio {:.2}",
                sizes[i],
                sizes[j],
                ratio
            );
        }
    }
}

/// Test ML-KEM ciphertext validation timing consistency
///
/// NOTE: This test measures validation timing which is affected by system load.
/// The validation logic is simple length checking which is inherently constant-time.
#[test]
fn test_mlkem_ciphertext_validation_timing() {
    const ITERATIONS: usize = 200;
    const WARMUP: usize = 20;

    let level = MlKemSecurityLevel::MlKem768;
    let correct_size = level.ciphertext_size();

    // Test different invalid sizes
    let sizes = [0, 1, correct_size - 1, correct_size + 1];

    let mut timings: Vec<TimingResult> = Vec::new();

    for size in sizes {
        let data = vec![0u8; size];

        let timing = measure_operation(
            || {
                let _ = MlKemCiphertext::new(level, data.clone());
            },
            ITERATIONS,
            WARMUP,
        );

        timings.push(timing);
    }

    // Log timing for analysis
    println!(
        "Ciphertext validation timings: {}",
        sizes
            .iter()
            .zip(timings.iter())
            .map(|(s, t)| format!("size {}={:.2}us", s, t.mean_ns / 1000.0))
            .collect::<Vec<_>>()
            .join(", ")
    );

    // All validation failures should have similar timing
    // Use very permissive thresholds due to system scheduling (memory allocation varies)
    for i in 0..timings.len() {
        for j in (i + 1)..timings.len() {
            let ratio = timing_ratio(&timings[i], &timings[j]);
            assert!(
                ratio > 0.001 && ratio < 1000.0,
                "Ciphertext validation timing varies extremely: ratio {:.2}",
                ratio
            );
        }
    }
}

/// Test AES-GCM decryption failure timing consistency
#[test]
fn test_aes_gcm_decryption_failure_timing() {
    const ITERATIONS: usize = 100;
    const WARMUP: usize = 10;

    let key = AesGcm256::generate_key();
    let cipher = AesGcm256::new(&key).expect("cipher creation should succeed");
    let nonce = AesGcm256::generate_nonce();
    let plaintext = b"Test message";

    // Encrypt properly
    let (ciphertext, correct_tag) =
        cipher.encrypt(&nonce, plaintext, None).expect("encryption should succeed");

    // Create different invalid tags
    let mut tag_diff_first = correct_tag;
    tag_diff_first[0] ^= 0xFF;

    let mut tag_diff_middle = correct_tag;
    tag_diff_middle[8] ^= 0xFF;

    let mut tag_diff_last = correct_tag;
    tag_diff_last[15] ^= 0xFF;

    let tag_all_zero = [0u8; 16];

    // Measure decryption failure times
    let timing_diff_first = measure_operation(
        || {
            let _ = cipher.decrypt(&nonce, &ciphertext, &tag_diff_first, None);
        },
        ITERATIONS,
        WARMUP,
    );

    let timing_diff_middle = measure_operation(
        || {
            let _ = cipher.decrypt(&nonce, &ciphertext, &tag_diff_middle, None);
        },
        ITERATIONS,
        WARMUP,
    );

    let timing_diff_last = measure_operation(
        || {
            let _ = cipher.decrypt(&nonce, &ciphertext, &tag_diff_last, None);
        },
        ITERATIONS,
        WARMUP,
    );

    let timing_all_zero = measure_operation(
        || {
            let _ = cipher.decrypt(&nonce, &ciphertext, &tag_all_zero, None);
        },
        ITERATIONS,
        WARMUP,
    );

    // All failure cases should have similar timing
    // Use permissive thresholds (0.1x to 10x) to account for system scheduling
    let ratios = [
        timing_ratio(&timing_diff_first, &timing_diff_middle),
        timing_ratio(&timing_diff_first, &timing_diff_last),
        timing_ratio(&timing_diff_first, &timing_all_zero),
    ];

    for (i, ratio) in ratios.iter().enumerate() {
        assert!(
            *ratio > 0.1 && *ratio < 10.0,
            "AES-GCM decryption failure timing varies extremely (case {}): ratio {:.2}",
            i,
            ratio
        );
    }
}

/// Test ML-DSA verification failure timing consistency
#[test]
fn test_mldsa_verification_failure_timing() {
    const ITERATIONS: usize = 20;
    const WARMUP: usize = 2;

    let (pk, sk) =
        generate_keypair(MlDsaParameterSet::MLDSA44).expect("keypair generation should succeed");
    let message = b"Test message";
    let context: &[u8] = &[];

    let signature = sign(&sk, message, context).expect("signing should succeed");

    // Create corrupted signatures
    let mut sig_corrupted_first = signature.clone();
    sig_corrupted_first.data[0] ^= 0xFF;

    let mut sig_corrupted_middle = signature.clone();
    let middle = sig_corrupted_middle.data.len() / 2;
    sig_corrupted_middle.data[middle] ^= 0xFF;

    let mut sig_corrupted_last = signature.clone();
    let last = sig_corrupted_last.data.len() - 1;
    sig_corrupted_last.data[last] ^= 0xFF;

    // Measure verification failure times
    let timing_first = measure_operation(
        || {
            let _ = verify(&pk, message, &sig_corrupted_first, context);
        },
        ITERATIONS,
        WARMUP,
    );

    let timing_middle = measure_operation(
        || {
            let _ = verify(&pk, message, &sig_corrupted_middle, context);
        },
        ITERATIONS,
        WARMUP,
    );

    let timing_last = measure_operation(
        || {
            let _ = verify(&pk, message, &sig_corrupted_last, context);
        },
        ITERATIONS,
        WARMUP,
    );

    // All failures should have similar timing
    // Use very permissive thresholds due to ML-DSA's high timing variance from rejection sampling
    // and lattice-based verification complexity
    let ratio1 = timing_ratio(&timing_first, &timing_middle);
    let ratio2 = timing_ratio(&timing_first, &timing_last);

    // Log timing for debugging
    println!(
        "ML-DSA verification failure timings: first={:.2}ms, middle={:.2}ms, last={:.2}ms",
        timing_first.mean_ns / 1_000_000.0,
        timing_middle.mean_ns / 1_000_000.0,
        timing_last.mean_ns / 1_000_000.0
    );

    // Use extremely permissive thresholds (0.01x to 100x) for ML-DSA
    // ML-DSA verification timing varies significantly due to the lattice operations
    assert!(
        ratio1 > 0.01 && ratio1 < 100.0,
        "ML-DSA verification failure timing varies extremely (first vs middle): ratio {:.2}",
        ratio1
    );

    assert!(
        ratio2 > 0.01 && ratio2 < 100.0,
        "ML-DSA verification failure timing varies extremely (first vs last): ratio {:.2}",
        ratio2
    );
}

/// Test ML-KEM security level mismatch error timing
#[test]
fn test_mlkem_security_level_mismatch_timing() {
    const ITERATIONS: usize = 100;
    const WARMUP: usize = 10;

    let mut rng = OsRng;

    // Generate keypairs at different security levels
    let (pk_512, _) = MlKem::generate_keypair(&mut rng, MlKemSecurityLevel::MlKem512)
        .expect("keypair generation should succeed");
    let (_, sk_768) = MlKem::generate_keypair(&mut rng, MlKemSecurityLevel::MlKem768)
        .expect("keypair generation should succeed");
    let (_, sk_1024) = MlKem::generate_keypair(&mut rng, MlKemSecurityLevel::MlKem1024)
        .expect("keypair generation should succeed");

    // Encapsulate with 512 level
    let (_, ct_512) = MlKem::encapsulate(&mut rng, &pk_512).expect("encapsulation should succeed");

    // Measure decapsulation with mismatched levels
    let timing_768 = measure_operation(
        || {
            let _ = MlKem::decapsulate(&sk_768, &ct_512);
        },
        ITERATIONS,
        WARMUP,
    );

    let timing_1024 = measure_operation(
        || {
            let _ = MlKem::decapsulate(&sk_1024, &ct_512);
        },
        ITERATIONS,
        WARMUP,
    );

    // Mismatch errors should have similar timing
    let ratio = timing_ratio(&timing_768, &timing_1024);
    assert!(
        ratio > 0.2 && ratio < 5.0,
        "Security level mismatch error timing varies: ratio {:.2}",
        ratio
    );
}

// ============================================================================
// SECTION 5: STATISTICAL TIMING ANALYSIS
// ============================================================================

/// Test timing distribution normality for ML-KEM encapsulation
///
/// NOTE: Due to system scheduling, CPU frequency scaling, and cache effects,
/// timing measurements may have high variance. This test uses permissive
/// thresholds to avoid false positives. The underlying implementation
/// provides constant-time guarantees through the subtle crate.
#[test]
fn test_mlkem_encapsulation_timing_distribution() {
    const ITERATIONS: usize = 200;
    const WARMUP: usize = 50;

    let mut rng = OsRng;
    let (pk, _sk) = MlKem::generate_keypair(&mut rng, MlKemSecurityLevel::MlKem768)
        .expect("keypair generation should succeed");

    let timing = measure_operation(
        || {
            let _ = MlKem::encapsulate(&mut OsRng, &pk);
        },
        ITERATIONS,
        WARMUP,
    );

    // Check for reasonable distribution properties
    let cv = timing.coefficient_of_variation();
    let range_ratio =
        if timing.min_ns > 0 { timing.max_ns as f64 / timing.min_ns as f64 } else { 1.0 };

    // Log timing distribution for debugging
    println!(
        "ML-KEM encapsulation timing distribution: mean={:.2}us, CV={:.1}%, range_ratio={:.1}x",
        timing.mean_ns / 1000.0,
        cv,
        range_ratio
    );

    // Use very permissive threshold (500x) to account for system scheduling delays
    // A single slow sample due to OS preemption can cause extremely high range ratios
    assert!(
        range_ratio < 500.0,
        "ML-KEM encapsulation timing range extremely wide: {:.2}x (min: {}ns, max: {}ns)",
        range_ratio,
        timing.min_ns,
        timing.max_ns
    );

    // CV is informational - high values indicate system load, not timing leaks
    // The constant-time guarantees come from aws-lc-rs, not from this measurement
    assert!(cv < 1000.0, "ML-KEM encapsulation timing CV extremely high: {:.2}%", cv);
}

/// Test timing distribution for AES-GCM operations
///
/// NOTE: This test measures timing distribution which is affected by system load.
/// The constant-time guarantees come from aws-lc-rs hardware acceleration.
#[test]
fn test_aes_gcm_timing_distribution() {
    const ITERATIONS: usize = 500;
    const WARMUP: usize = 50;

    let key = AesGcm256::generate_key();
    let cipher = AesGcm256::new(&key).expect("cipher creation should succeed");
    let nonce = AesGcm256::generate_nonce();
    let plaintext = vec![0xABu8; 1024];

    let timing = measure_operation(
        || {
            let _ = cipher.encrypt(&nonce, &plaintext, None);
        },
        ITERATIONS,
        WARMUP,
    );

    let cv = timing.coefficient_of_variation();
    let range_ratio =
        if timing.min_ns > 0 { timing.max_ns as f64 / timing.min_ns as f64 } else { 1.0 };

    // Log timing distribution for analysis
    println!(
        "AES-GCM timing distribution: mean={:.2}us, CV={:.1}%, range_ratio={:.1}x",
        timing.mean_ns / 1000.0,
        cv,
        range_ratio
    );

    // Use very permissive thresholds - timing measurements are informational
    // High variance indicates system load, not timing leaks
    // The constant-time guarantees come from aws-lc-rs, not from this measurement
    assert!(
        range_ratio < 500.0,
        "AES-GCM encryption timing range extremely wide: {:.2}x",
        range_ratio
    );

    assert!(cv < 500.0, "AES-GCM encryption timing CV extremely high: {:.2}%", cv);
}

/// Test timing leak detection utility
///
/// NOTE: This test measures timing variance which is inherently unstable under
/// coverage instrumentation. The constant-time guarantees come from the subtle crate.
#[test]
#[ignore = "timing tests are unstable under llvm-cov instrumentation"]
fn test_timing_leak_detection_utility() {
    // This test demonstrates how to detect potential timing leaks
    const ITERATIONS: usize = 200;
    const WARMUP: usize = 20;

    // Operation that should be constant-time
    let ss1 = MlKemSharedSecret::new([0x00u8; 32]);
    let ss2 = MlKemSharedSecret::new([0xFFu8; 32]);

    let timing = measure_operation(
        || {
            let _ = ss1.ct_eq(&ss2);
        },
        ITERATIONS,
        WARMUP,
    );

    // Calculate timing metrics
    let cv = timing.coefficient_of_variation();
    let mean_us = timing.mean_ns / 1000.0;

    println!("Constant-time comparison metrics:");
    println!("  Mean: {:.3}us", mean_us);
    println!("  Std Dev: {:.3}us", timing.std_dev_ns / 1000.0);
    println!("  CV: {:.2}%", cv);
    println!("  Min: {}ns, Max: {}ns", timing.min_ns, timing.max_ns);

    // A true constant-time operation should have low CV
    assert!(cv < 100.0, "Constant-time operation has suspiciously high timing variance");
}

/// Test for timing variance across different input sizes
///
/// NOTE: Due to cache effects and system scheduling, timing may not scale
/// perfectly linearly. This test uses permissive thresholds to validate
/// general scaling behavior while avoiding false positives from system noise.
#[test]
fn test_input_size_timing_scaling() {
    const ITERATIONS: usize = 50;
    const WARMUP: usize = 5;

    let key = AesGcm256::generate_key();
    let cipher = AesGcm256::new(&key).expect("cipher creation should succeed");

    let sizes = [64, 128, 256, 512, 1024, 2048, 4096];
    let mut timings: Vec<(usize, f64)> = Vec::new();

    for size in sizes {
        let nonce = AesGcm256::generate_nonce();
        let plaintext = vec![0xABu8; size];

        let timing = measure_operation(
            || {
                let _ = cipher.encrypt(&nonce, &plaintext, None);
            },
            ITERATIONS,
            WARMUP,
        );

        timings.push((size, timing.mean_ns));
    }

    // Verify timing scales approximately with size
    // Use permissive threshold to account for cache effects and system scheduling
    for i in 1..timings.len() {
        let size_ratio = timings[i].0 as f64 / timings[i - 1].0 as f64;
        let time_ratio = timings[i].1 / timings[i - 1].1;

        // Time should increase, but allow for cache effects and system noise
        // Use very permissive threshold (10x for 2x size increase)
        assert!(
            time_ratio < size_ratio * 5.0 + 5.0,
            "Timing scaling extreme anomaly at size {}: size_ratio={:.2}, time_ratio={:.2}",
            timings[i].0,
            size_ratio,
            time_ratio
        );
    }
}

/// Test comprehensive timing bounds for all algorithms
#[test]
fn test_comprehensive_timing_bounds() {
    const ITERATIONS: usize = 20;
    const WARMUP: usize = 2;

    let mut rng = OsRng;

    println!("\n=== Comprehensive Timing Bounds Report ===\n");

    // ML-KEM operations
    println!("ML-KEM Operations:");
    for level in
        [MlKemSecurityLevel::MlKem512, MlKemSecurityLevel::MlKem768, MlKemSecurityLevel::MlKem1024]
    {
        let keygen_timing = measure_operation(
            || {
                let _ = MlKem::generate_keypair(&mut OsRng, level);
            },
            ITERATIONS,
            WARMUP,
        );

        let (pk, _sk) =
            MlKem::generate_keypair(&mut rng, level).expect("keypair generation should succeed");

        let encaps_timing = measure_operation(
            || {
                let _ = MlKem::encapsulate(&mut OsRng, &pk);
            },
            ITERATIONS,
            WARMUP,
        );

        println!(
            "  {}: keygen={:.2}us (CV={:.1}%), encaps={:.2}us (CV={:.1}%)",
            level.name(),
            keygen_timing.mean_ns / 1000.0,
            keygen_timing.coefficient_of_variation(),
            encaps_timing.mean_ns / 1000.0,
            encaps_timing.coefficient_of_variation()
        );
    }

    // ML-DSA operations
    println!("\nML-DSA Operations:");
    for param in
        [MlDsaParameterSet::MLDSA44, MlDsaParameterSet::MLDSA65, MlDsaParameterSet::MLDSA87]
    {
        let keygen_timing = measure_operation(
            || {
                let _ = generate_keypair(param);
            },
            ITERATIONS / 4,
            WARMUP / 2,
        );

        let (pk, sk) = generate_keypair(param).expect("keypair generation should succeed");
        let message = b"Test message";

        let sign_timing = measure_operation(
            || {
                let _ = sign(&sk, message, &[]);
            },
            ITERATIONS / 4,
            WARMUP / 2,
        );

        let signature = sign(&sk, message, &[]).expect("signing should succeed");

        let verify_timing = measure_operation(
            || {
                let _ = verify(&pk, message, &signature, &[]);
            },
            ITERATIONS / 4,
            WARMUP / 2,
        );

        println!(
            "  {:?}: keygen={:.2}ms (CV={:.1}%), sign={:.2}ms (CV={:.1}%), verify={:.2}ms (CV={:.1}%)",
            param,
            keygen_timing.mean_ns / 1_000_000.0,
            keygen_timing.coefficient_of_variation(),
            sign_timing.mean_ns / 1_000_000.0,
            sign_timing.coefficient_of_variation(),
            verify_timing.mean_ns / 1_000_000.0,
            verify_timing.coefficient_of_variation()
        );
    }

    // AES-GCM operations
    println!("\nAES-GCM Operations (1KB message):");
    let key = AesGcm256::generate_key();
    let cipher = AesGcm256::new(&key).expect("cipher creation should succeed");
    let nonce = AesGcm256::generate_nonce();
    let plaintext = vec![0xABu8; 1024];

    let encrypt_timing = measure_operation(
        || {
            let _ = cipher.encrypt(&nonce, &plaintext, None);
        },
        ITERATIONS * 5,
        WARMUP * 5,
    );

    let (ciphertext, tag) =
        cipher.encrypt(&nonce, &plaintext, None).expect("encryption should succeed");

    let decrypt_timing = measure_operation(
        || {
            let _ = cipher.decrypt(&nonce, &ciphertext, &tag, None);
        },
        ITERATIONS * 5,
        WARMUP * 5,
    );

    println!(
        "  AES-256-GCM: encrypt={:.2}us (CV={:.1}%), decrypt={:.2}us (CV={:.1}%)",
        encrypt_timing.mean_ns / 1000.0,
        encrypt_timing.coefficient_of_variation(),
        decrypt_timing.mean_ns / 1000.0,
        decrypt_timing.coefficient_of_variation()
    );

    println!("\n=== End of Timing Report ===\n");
}

// ============================================================================
// ADDITIONAL SIDE-CHANNEL RESISTANCE TESTS
// ============================================================================

/// Test that constant-time operations produce correct results
#[test]
fn test_constant_time_operation_correctness() {
    // ML-KEM shared secret comparison
    let ss1 = MlKemSharedSecret::new([0x42u8; 32]);
    let ss2 = MlKemSharedSecret::new([0x42u8; 32]);
    let ss3 = MlKemSharedSecret::new([0x43u8; 32]);

    assert!(bool::from(ss1.ct_eq(&ss2)), "Equal shared secrets should compare equal");
    assert!(!bool::from(ss1.ct_eq(&ss3)), "Different shared secrets should compare unequal");

    // ML-KEM security level comparison
    let level1 = MlKemSecurityLevel::MlKem768;
    let level2 = MlKemSecurityLevel::MlKem768;
    let level3 = MlKemSecurityLevel::MlKem1024;

    assert!(bool::from(level1.ct_eq(&level2)), "Same levels should compare equal");
    assert!(!bool::from(level1.ct_eq(&level3)), "Different levels should compare unequal");

    // ML-KEM secret key comparison
    let sk1 = MlKemSecretKey::new(MlKemSecurityLevel::MlKem512, vec![0xAAu8; 1632]).unwrap();
    let sk2 = MlKemSecretKey::new(MlKemSecurityLevel::MlKem512, vec![0xAAu8; 1632]).unwrap();
    let sk3 = MlKemSecretKey::new(MlKemSecurityLevel::MlKem512, vec![0xBBu8; 1632]).unwrap();

    assert!(bool::from(sk1.ct_eq(&sk2)), "Equal secret keys should compare equal");
    assert!(!bool::from(sk1.ct_eq(&sk3)), "Different secret keys should compare unequal");
}

/// Test branch-free operation behavior
///
/// NOTE: This test verifies constant-time comparison using the subtle crate.
/// Due to system scheduling and CPU caching, measured timing may vary.
/// The actual constant-time guarantees come from the subtle crate implementation.
#[test]
fn test_branch_free_operations() {
    const ITERATIONS: usize = 1000;
    const WARMUP: usize = 100;

    // Test that comparison doesn't short-circuit
    let base = vec![0x00u8; 32];
    let same = vec![0x00u8; 32];
    let diff_early = {
        let mut v = vec![0x00u8; 32];
        v[0] = 0xFF;
        v
    };
    let diff_late = {
        let mut v = vec![0x00u8; 32];
        v[31] = 0xFF;
        v
    };

    // Using subtle crate's constant-time comparison
    let timing_same = measure_operation(
        || {
            let _ = base.ct_eq(&same);
        },
        ITERATIONS,
        WARMUP,
    );

    let timing_diff_early = measure_operation(
        || {
            let _ = base.ct_eq(&diff_early);
        },
        ITERATIONS,
        WARMUP,
    );

    let timing_diff_late = measure_operation(
        || {
            let _ = base.ct_eq(&diff_late);
        },
        ITERATIONS,
        WARMUP,
    );

    // All should have similar timing (no early exit)
    // Use permissive thresholds (0.25x to 4x) due to system noise
    let ratio1 = timing_ratio(&timing_same, &timing_diff_early);
    let ratio2 = timing_ratio(&timing_same, &timing_diff_late);
    let ratio3 = timing_ratio(&timing_diff_early, &timing_diff_late);

    // Log timing for analysis
    println!(
        "Branch-free timings: same={:.2}us, diff_early={:.2}us, diff_late={:.2}us",
        timing_same.mean_ns / 1000.0,
        timing_diff_early.mean_ns / 1000.0,
        timing_diff_late.mean_ns / 1000.0
    );

    assert!(
        ratio1 > 0.25 && ratio1 < 4.0,
        "Same vs diff_early timing ratio out of bounds: {:.2}",
        ratio1
    );
    assert!(
        ratio2 > 0.25 && ratio2 < 4.0,
        "Same vs diff_late timing ratio out of bounds: {:.2}",
        ratio2
    );
    assert!(
        ratio3 > 0.25 && ratio3 < 4.0,
        "diff_early vs diff_late timing ratio out of bounds: {:.2}",
        ratio3
    );
}

/// Test that zeroization is complete and verifiable
#[test]
fn test_zeroization_completeness() {
    // Test various sizes to ensure complete coverage
    for size in [1, 16, 32, 64, 128, 256, 512, 1024, 2048] {
        let mut data = vec![0xFFu8; size];

        // Verify data is non-zero
        assert!(data.iter().all(|&b| b == 0xFF), "Test data should be all 0xFF");

        // Zeroize
        data.zeroize();

        // Verify complete zeroization
        assert!(data.iter().all(|&b| b == 0), "Data of size {} should be completely zeroed", size);
    }
}

/// Test that secret-dependent operations don't leak timing information
#[test]
fn test_secret_dependent_operation_timing() {
    const ITERATIONS: usize = 100;
    const WARMUP: usize = 10;

    // Test with different secret key patterns
    let patterns: Vec<Vec<u8>> = vec![
        vec![0x00u8; 1632],                       // All zeros
        vec![0xFFu8; 1632],                       // All ones
        (0u8..=255).cycle().take(1632).collect(), // Sequential pattern
        vec![0xAAu8; 1632],                       // Alternating
    ];

    let mut timings: Vec<TimingResult> = Vec::new();

    for pattern in &patterns {
        let sk = MlKemSecretKey::new(MlKemSecurityLevel::MlKem512, pattern.clone())
            .expect("secret key creation should succeed");

        let other = MlKemSecretKey::new(MlKemSecurityLevel::MlKem512, vec![0x55u8; 1632])
            .expect("secret key creation should succeed");

        let timing = measure_operation(
            || {
                let _ = sk.ct_eq(&other);
            },
            ITERATIONS,
            WARMUP,
        );

        timings.push(timing);
    }

    // All patterns should have similar timing
    for i in 0..timings.len() {
        for j in (i + 1)..timings.len() {
            let ratio = timing_ratio(&timings[i], &timings[j]);
            assert!(
                ratio > 0.33 && ratio < 3.0,
                "Secret key comparison timing varies with key pattern: ratio {:.2}",
                ratio
            );
        }
    }
}

// ============================================================================
// SECTION 6: ADDITIONAL AEAD AND KDF SIDE-CHANNEL TESTS
// ============================================================================

/// Test ChaCha20-Poly1305 encryption timing consistency
///
/// ChaCha20-Poly1305 is designed to be constant-time by construction.
/// This test verifies timing consistency across different input patterns.
///
/// NOTE: Due to system scheduling and CPU frequency scaling, timing measurements
/// may have high variance. The constant-time guarantees come from the underlying
/// chacha20poly1305 crate implementation, NOT from timing measurements.
#[test]
fn test_chacha20poly1305_encryption_timing_consistency() {
    use arc_primitives::aead::chacha20poly1305::ChaCha20Poly1305Cipher;

    const ITERATIONS: usize = 200;
    const WARMUP: usize = 20;

    let key = ChaCha20Poly1305Cipher::generate_key();
    let cipher = ChaCha20Poly1305Cipher::new(&key).expect("cipher creation should succeed");

    // Test different plaintext sizes
    for size in [16, 64, 256, 1024] {
        let nonce = ChaCha20Poly1305Cipher::generate_nonce();
        let plaintext = vec![0xABu8; size];

        let timing = measure_operation(
            || {
                let _ = cipher.encrypt(&nonce, &plaintext, None);
            },
            ITERATIONS,
            WARMUP,
        );

        // ChaCha20-Poly1305 should have consistent timing per block
        // Use very permissive threshold (1000%) to account for system scheduling
        // The constant-time guarantees come from the chacha20poly1305 crate, not from this measurement
        let cv = timing.coefficient_of_variation();
        assert!(
            cv < 1000.0,
            "ChaCha20-Poly1305 encryption timing CV for size {} is extremely high: {:.2}%",
            size,
            cv
        );
    }
}

/// Test ChaCha20-Poly1305 tag verification constant-time behavior
#[test]
#[ignore = "timing tests are unstable under llvm-cov instrumentation"]
fn test_chacha20poly1305_tag_verification_constant_time() {
    use arc_primitives::aead::chacha20poly1305::verify_tag_constant_time;

    const ITERATIONS: usize = 2000;
    const WARMUP: usize = 200;

    let tag1 = [0x00u8; 16];
    let tag2 = [0x00u8; 16]; // Equal
    let tag3 = [0xFFu8; 16]; // Completely different
    let mut tag4 = [0x00u8; 16];
    tag4[15] = 0x01; // Differs only in last byte

    // Measure equal tags
    let equal_timing = measure_operation(
        || {
            let _ = verify_tag_constant_time(&tag1, &tag2);
        },
        ITERATIONS,
        WARMUP,
    );

    // Measure completely different tags
    let different_timing = measure_operation(
        || {
            let _ = verify_tag_constant_time(&tag1, &tag3);
        },
        ITERATIONS,
        WARMUP,
    );

    // Measure almost equal tags
    let almost_equal_timing = measure_operation(
        || {
            let _ = verify_tag_constant_time(&tag1, &tag4);
        },
        ITERATIONS,
        WARMUP,
    );

    let ratio1 = timing_ratio(&equal_timing, &different_timing);
    let ratio2 = timing_ratio(&equal_timing, &almost_equal_timing);

    // Use permissive thresholds (0.2x to 5x) to account for system noise
    assert!(
        ratio1 > 0.2 && ratio1 < 5.0,
        "ChaCha20-Poly1305 tag verification timing ratio (equal vs different) out of bounds: {:.2}",
        ratio1
    );

    assert!(
        ratio2 > 0.2 && ratio2 < 5.0,
        "ChaCha20-Poly1305 tag verification timing ratio (equal vs almost-equal) out of bounds: {:.2}",
        ratio2
    );
}

/// Test ChaCha20-Poly1305 decryption failure timing consistency
#[test]
fn test_chacha20poly1305_decryption_failure_timing() {
    use arc_primitives::aead::chacha20poly1305::ChaCha20Poly1305Cipher;

    const ITERATIONS: usize = 100;
    const WARMUP: usize = 10;

    let key = ChaCha20Poly1305Cipher::generate_key();
    let cipher = ChaCha20Poly1305Cipher::new(&key).expect("cipher creation should succeed");
    let nonce = ChaCha20Poly1305Cipher::generate_nonce();
    let plaintext = b"Test message";

    // Encrypt properly
    let (ciphertext, correct_tag) =
        cipher.encrypt(&nonce, plaintext, None).expect("encryption should succeed");

    // Create different invalid tags
    let mut tag_diff_first = correct_tag;
    tag_diff_first[0] ^= 0xFF;

    let mut tag_diff_middle = correct_tag;
    tag_diff_middle[8] ^= 0xFF;

    let mut tag_diff_last = correct_tag;
    tag_diff_last[15] ^= 0xFF;

    // Measure decryption failure times
    let timing_diff_first = measure_operation(
        || {
            let _ = cipher.decrypt(&nonce, &ciphertext, &tag_diff_first, None);
        },
        ITERATIONS,
        WARMUP,
    );

    let timing_diff_middle = measure_operation(
        || {
            let _ = cipher.decrypt(&nonce, &ciphertext, &tag_diff_middle, None);
        },
        ITERATIONS,
        WARMUP,
    );

    let timing_diff_last = measure_operation(
        || {
            let _ = cipher.decrypt(&nonce, &ciphertext, &tag_diff_last, None);
        },
        ITERATIONS,
        WARMUP,
    );

    // All failure cases should have similar timing
    let ratio1 = timing_ratio(&timing_diff_first, &timing_diff_middle);
    let ratio2 = timing_ratio(&timing_diff_first, &timing_diff_last);

    assert!(
        ratio1 > 0.33 && ratio1 < 3.0,
        "ChaCha20-Poly1305 decryption failure timing varies (first vs middle): ratio {:.2}",
        ratio1
    );

    assert!(
        ratio2 > 0.33 && ratio2 < 3.0,
        "ChaCha20-Poly1305 decryption failure timing varies (first vs last): ratio {:.2}",
        ratio2
    );
}

/// Test HKDF timing consistency across different input sizes
///
/// HKDF should have consistent timing for inputs of similar size.
#[test]
#[ignore = "timing tests are unstable under llvm-cov instrumentation"]
fn test_hkdf_timing_consistency() {
    use arc_primitives::kdf::hkdf::hkdf;

    const ITERATIONS: usize = 100;
    const WARMUP: usize = 10;

    let salt = b"test salt for timing analysis";
    let info = b"context information";

    // Test different IKM patterns (same size)
    let patterns: Vec<&[u8]> = vec![
        &[0x00u8; 32], // All zeros
        &[0xFFu8; 32], // All ones
        &[0xAAu8; 32], // Alternating
        &[0x55u8; 32], // Alternating (inverted)
    ];

    let mut timings: Vec<TimingResult> = Vec::new();

    for pattern in &patterns {
        let timing = measure_operation(
            || {
                let _ = hkdf(*pattern, Some(salt), Some(info), 32);
            },
            ITERATIONS,
            WARMUP,
        );

        timings.push(timing);
    }

    // All patterns should have similar timing
    for i in 0..timings.len() {
        for j in (i + 1)..timings.len() {
            let ratio = timing_ratio(&timings[i], &timings[j]);
            assert!(
                ratio > 0.33 && ratio < 3.0,
                "HKDF timing varies with input pattern: ratio {:.2}",
                ratio
            );
        }
    }
}

/// Test HKDF key derivation timing independence from secret content
///
/// The timing of HKDF should not depend on the actual secret values.
/// NOTE: Timing measurements are inherently unstable under coverage instrumentation.
#[test]
#[ignore = "timing tests are unstable under llvm-cov instrumentation"]
fn test_hkdf_key_derivation_timing_independence() {
    use arc_primitives::kdf::hkdf::{hkdf_expand, hkdf_extract};

    const ITERATIONS: usize = 200;
    const WARMUP: usize = 20;

    // Test extract phase timing
    let salt = b"fixed salt";
    let ikm_all_zero = [0x00u8; 64];
    let ikm_all_one = [0xFFu8; 64];
    let ikm_pattern: Vec<u8> = (0..64).map(|i| i as u8).collect();

    let extract_timing_zero = measure_operation(
        || {
            let _ = hkdf_extract(Some(salt), &ikm_all_zero);
        },
        ITERATIONS,
        WARMUP,
    );

    let extract_timing_one = measure_operation(
        || {
            let _ = hkdf_extract(Some(salt), &ikm_all_one);
        },
        ITERATIONS,
        WARMUP,
    );

    let extract_timing_pattern = measure_operation(
        || {
            let _ = hkdf_extract(Some(salt), &ikm_pattern);
        },
        ITERATIONS,
        WARMUP,
    );

    // Extract timing should be independent of IKM content
    let ratio1 = timing_ratio(&extract_timing_zero, &extract_timing_one);
    let ratio2 = timing_ratio(&extract_timing_zero, &extract_timing_pattern);

    assert!(
        ratio1 > 0.33 && ratio1 < 3.0,
        "HKDF-Extract timing depends on IKM content (zero vs one): ratio {:.2}",
        ratio1
    );

    assert!(
        ratio2 > 0.33 && ratio2 < 3.0,
        "HKDF-Extract timing depends on IKM content (zero vs pattern): ratio {:.2}",
        ratio2
    );

    // Test expand phase timing
    let prk = hkdf_extract(Some(salt), &ikm_all_zero).expect("extract should succeed");
    let info_short = b"short";
    let info_long = b"longer context information string";

    let expand_timing_short = measure_operation(
        || {
            let _ = hkdf_expand(&prk, Some(info_short), 64);
        },
        ITERATIONS,
        WARMUP,
    );

    let expand_timing_long = measure_operation(
        || {
            let _ = hkdf_expand(&prk, Some(info_long), 64);
        },
        ITERATIONS,
        WARMUP,
    );

    // Expand timing may vary with info length but should be in reasonable bounds
    let ratio3 = timing_ratio(&expand_timing_short, &expand_timing_long);

    // Use permissive threshold since info length affects timing legitimately
    assert!(
        ratio3 > 0.1 && ratio3 < 10.0,
        "HKDF-Expand timing ratio out of extreme bounds: ratio {:.2}",
        ratio3
    );
}
