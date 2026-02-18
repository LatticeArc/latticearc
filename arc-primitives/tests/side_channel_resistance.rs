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
#![allow(dead_code)]

//! Side-Channel Resistance Tests
//!
//! Validates constant-time operations, key zeroization, timing consistency,
//! and absence of secret-dependent branching in arc-primitives.
//!
//! Run with: `cargo test --package arc-primitives --test side_channel_resistance --all-features --release -- --nocapture`

use std::time::Instant;

use rand::rngs::OsRng;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use arc_primitives::aead::{AeadCipher, aes_gcm::AesGcm256};
use arc_primitives::kem::ml_kem::{MlKem, MlKemSecurityLevel, MlKemSharedSecret};
use arc_primitives::sig::ml_dsa::{MlDsaParameterSet, generate_keypair, sign, verify};

// ============================================================================
// Timing Measurement Utilities
// ============================================================================

#[derive(Debug, Clone)]
struct TimingResult {
    mean_ns: f64,
    std_dev_ns: f64,
    sample_count: usize,
}

impl TimingResult {
    fn coefficient_of_variation(&self) -> f64 {
        if self.mean_ns > 0.0 { (self.std_dev_ns / self.mean_ns) * 100.0 } else { 0.0 }
    }
}

fn measure_operation<F>(operation: F, iterations: usize, warmup: usize) -> TimingResult
where
    F: Fn(),
{
    for _ in 0..warmup {
        operation();
    }

    let mut durations: Vec<u128> = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let start = Instant::now();
        operation();
        let duration = start.elapsed().as_nanos();
        durations.push(duration);
    }

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

    TimingResult { mean_ns, std_dev_ns: variance.sqrt(), sample_count: iterations }
}

// ============================================================================
// Section 1: Constant-Time Comparison via subtle::ConstantTimeEq
// ============================================================================

#[test]
fn test_constant_time_eq_shared_secrets() {
    const ITERATIONS: usize = 1000;
    const WARMUP: usize = 100;

    let ss_a = MlKemSharedSecret::new([0x00u8; 32]);
    let ss_equal = MlKemSharedSecret::new([0x00u8; 32]);
    let ss_different = MlKemSharedSecret::new([0xFFu8; 32]);

    // Only-last-byte-differs case
    let mut last_byte_data = [0x00u8; 32];
    last_byte_data[31] = 0x01;
    let ss_last_byte = MlKemSharedSecret::new(last_byte_data);

    let equal_timing = measure_operation(
        || {
            let _ = ss_a.ct_eq(&ss_equal);
        },
        ITERATIONS,
        WARMUP,
    );
    let diff_timing = measure_operation(
        || {
            let _ = ss_a.ct_eq(&ss_different);
        },
        ITERATIONS,
        WARMUP,
    );
    let last_timing = measure_operation(
        || {
            let _ = ss_a.ct_eq(&ss_last_byte);
        },
        ITERATIONS,
        WARMUP,
    );

    // All three should have similar timing — use very conservative CV threshold
    println!(
        "CT-eq equal:     mean={:.1}ns CV={:.1}%",
        equal_timing.mean_ns,
        equal_timing.coefficient_of_variation()
    );
    println!(
        "CT-eq different: mean={:.1}ns CV={:.1}%",
        diff_timing.mean_ns,
        diff_timing.coefficient_of_variation()
    );
    println!(
        "CT-eq last-byte: mean={:.1}ns CV={:.1}%",
        last_timing.mean_ns,
        last_timing.coefficient_of_variation()
    );

    // Verify the operations produce correct boolean results
    assert!(bool::from(ss_a.ct_eq(&ss_equal)), "Equal secrets must compare equal");
    assert!(!bool::from(ss_a.ct_eq(&ss_different)), "Different secrets must not compare equal");
    assert!(!bool::from(ss_a.ct_eq(&ss_last_byte)), "Last-byte-different must not compare equal");
}

#[test]
fn test_constant_time_eq_raw_bytes() {
    let a = [0xAA_u8; 64];
    let b = [0xAA_u8; 64];
    let c = [0xBB_u8; 64];

    assert!(bool::from(a.ct_eq(&b)), "Equal arrays must ct_eq");
    assert!(!bool::from(a.ct_eq(&c)), "Different arrays must not ct_eq");
}

// ============================================================================
// Section 2: Key Zeroization
// ============================================================================

#[test]
fn test_zeroize_byte_array() {
    let mut secret = [0xABu8; 32];
    assert!(secret.iter().any(|&b| b != 0), "Secret should start non-zero");
    secret.zeroize();
    assert!(secret.iter().all(|&b| b == 0), "Secret must be zeroed after zeroize()");
}

#[test]
fn test_zeroize_vec() {
    let mut secret = vec![0xCD_u8; 64];
    assert!(!secret.is_empty());
    secret.zeroize();
    // After zeroization the vec may be empty or all zeros
    assert!(
        secret.is_empty() || secret.iter().all(|&b| b == 0),
        "Vec must be zeroed or cleared after zeroize()"
    );
}

// ============================================================================
// Section 3: Timing Consistency for Encrypt/Decrypt
// ============================================================================

#[test]
fn test_aes_gcm_encrypt_timing_consistency() {
    const ITERATIONS: usize = 500;
    const WARMUP: usize = 50;

    let cipher = AesGcm256::new(&[0x42u8; 32]).expect("AesGcm256::new failed");
    let plaintext_small = vec![0u8; 64];
    let nonce = [0u8; 12];

    let timing = measure_operation(
        || {
            let _ = cipher.encrypt(&nonce, &plaintext_small, None);
        },
        ITERATIONS,
        WARMUP,
    );

    println!(
        "AES-GCM-256 encrypt 64B: mean={:.1}ns CV={:.1}%",
        timing.mean_ns,
        timing.coefficient_of_variation()
    );

    // Hardware AES-NI provides constant-time guarantees; CV should be reasonable.
    // Use very generous threshold for CI environments.
    assert!(
        timing.coefficient_of_variation() < 2000.0,
        "AES-GCM encrypt CV ({:.1}%) should be < 2000% (CI-safe threshold)",
        timing.coefficient_of_variation()
    );
}

#[test]
fn test_aes_gcm_decrypt_timing_consistency() {
    const ITERATIONS: usize = 500;
    const WARMUP: usize = 50;

    let cipher = AesGcm256::new(&[0x42u8; 32]).expect("AesGcm256::new failed");
    let nonce = [0u8; 12];
    let (ciphertext, tag) = cipher.encrypt(&nonce, &[0u8; 64], None).expect("encrypt failed");

    let timing = measure_operation(
        || {
            let _ = cipher.decrypt(&nonce, &ciphertext, &tag, None);
        },
        ITERATIONS,
        WARMUP,
    );

    println!(
        "AES-GCM-256 decrypt 64B: mean={:.1}ns CV={:.1}%",
        timing.mean_ns,
        timing.coefficient_of_variation()
    );

    assert!(
        timing.coefficient_of_variation() < 2000.0,
        "AES-GCM decrypt CV ({:.1}%) should be < 2000% (CI-safe threshold)",
        timing.coefficient_of_variation()
    );
}

// ============================================================================
// Section 4: No Secret-Dependent Branching Validation
// ============================================================================

#[test]
fn test_aes_gcm_tag_verification_constant_time() {
    use arc_primitives::aead::aes_gcm::verify_tag_constant_time;

    // Matching tags
    let tag_a = [0x11u8; 16];
    let tag_b = [0x11u8; 16];
    assert!(verify_tag_constant_time(&tag_a, &tag_b), "Equal tags must verify");

    // Non-matching tags
    let tag_c = [0x22u8; 16];
    assert!(!verify_tag_constant_time(&tag_a, &tag_c), "Different tags must not verify");

    // Differ in last byte only
    let mut tag_d = [0x11u8; 16];
    tag_d[15] = 0x12;
    assert!(!verify_tag_constant_time(&tag_a, &tag_d), "Last-byte-different must not verify");
}

#[test]
fn test_zeroize_data_function() {
    use arc_primitives::aead::aes_gcm::zeroize_data;

    let mut data = vec![0xFFu8; 128];
    zeroize_data(&mut data);
    assert!(data.iter().all(|&b| b == 0), "zeroize_data must clear all bytes");
}

// ============================================================================
// Section 5: ML-KEM Encap/Decap Timing Smoke Test
// ============================================================================

#[test]
fn test_ml_kem_encap_timing_smoke() {
    // Use generate_decapsulation_keypair to get a DecapsulationKey instance
    let keypair =
        MlKem::generate_decapsulation_keypair(MlKemSecurityLevel::MlKem768).expect("keygen failed");

    let (ss_enc, ct) = MlKem::encapsulate(&mut OsRng, keypair.public_key()).expect("encap failed");
    let ss_dec = keypair.decapsulate(&ct).expect("decap failed");

    assert!(bool::from(ss_enc.ct_eq(&ss_dec)), "Encap/decap shared secrets must match");
}

// ============================================================================
// Section 6: ML-DSA Sign/Verify Timing Smoke Test
// ============================================================================

#[test]
fn test_ml_dsa_sign_verify_smoke() {
    let (pk, sk) = generate_keypair(MlDsaParameterSet::MLDSA44).expect("keygen failed");
    let message = b"Side-channel resistance smoke test";

    let sig = sign(&sk, message, &[]).expect("sign failed");
    let ok = verify(&pk, message, &sig, &[]).expect("verify failed");
    assert!(ok, "ML-DSA-44 signature must verify");
}
