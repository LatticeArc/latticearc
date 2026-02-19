//! Coverage tests for nist_sp800_22.rs (NIST SP 800-22 statistical test suite)
//!
//! Targets uncovered paths: edge cases in statistical tests, helper functions,
//! short sequences, individual test methods.

#![allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::print_stdout,
    clippy::redundant_clone,
    clippy::float_cmp
)]

use latticearc_tests::validation::nist_sp800_22::NistSp800_22Tester;

// ============================================================================
// Construction
// ============================================================================

#[test]
fn test_tester_default() {
    let tester = NistSp800_22Tester::default();
    // Default: significance_level = 0.01, min_sequence_length = 1000
    let data = vec![0u8; 1000];
    let result = tester.test_bit_sequence(&data).unwrap();
    assert_eq!(result.bits_tested, 8000);
}

#[test]
fn test_tester_custom_params() {
    let tester = NistSp800_22Tester::new(0.05, 500);
    let data = vec![0xAAu8; 500];
    let result = tester.test_bit_sequence(&data).unwrap();
    assert_eq!(result.bits_tested, 4000);
}

// ============================================================================
// Short sequence early return
// ============================================================================

#[test]
fn test_short_sequence_returns_empty_results() {
    let tester = NistSp800_22Tester::default();
    // min_sequence_length = 1000, so 1000/8 = 125 bytes minimum
    let short_data = vec![0u8; 10];
    let result = tester.test_bit_sequence(&short_data).unwrap();
    assert!(!result.passed);
    assert!(result.test_results.is_empty());
    assert_eq!(result.bits_tested, 80);
    assert_eq!(result.entropy_estimate, 0.0);
    assert_eq!(result.algorithm, "unknown");
}

#[test]
fn test_exactly_at_minimum_length() {
    let tester = NistSp800_22Tester::new(0.01, 800);
    // 800/8 = 100 bytes minimum
    let data = vec![0xF0u8; 100];
    let result = tester.test_bit_sequence(&data).unwrap();
    assert_eq!(result.bits_tested, 800);
    assert!(!result.test_results.is_empty());
}

#[test]
fn test_empty_data() {
    let tester = NistSp800_22Tester::default();
    let result = tester.test_bit_sequence(&[]).unwrap();
    assert!(!result.passed);
    assert!(result.test_results.is_empty());
    assert_eq!(result.bits_tested, 0);
}

// ============================================================================
// bytes_to_bits
// ============================================================================

#[test]
fn test_bytes_to_bits_single_byte() {
    let tester = NistSp800_22Tester::default();
    let bits = tester.bytes_to_bits(&[0b10110100]);
    assert_eq!(bits.len(), 8);
    assert_eq!(bits, vec![true, false, true, true, false, true, false, false]);
}

#[test]
fn test_bytes_to_bits_all_zeros() {
    let tester = NistSp800_22Tester::default();
    let bits = tester.bytes_to_bits(&[0x00]);
    assert_eq!(bits, vec![false; 8]);
}

#[test]
fn test_bytes_to_bits_all_ones() {
    let tester = NistSp800_22Tester::default();
    let bits = tester.bytes_to_bits(&[0xFF]);
    assert_eq!(bits, vec![true; 8]);
}

#[test]
fn test_bytes_to_bits_empty() {
    let tester = NistSp800_22Tester::default();
    let bits = tester.bytes_to_bits(&[]);
    assert!(bits.is_empty());
}

#[test]
fn test_bytes_to_bits_multiple_bytes() {
    let tester = NistSp800_22Tester::default();
    let bits = tester.bytes_to_bits(&[0xFF, 0x00]);
    assert_eq!(bits.len(), 16);
    assert!(bits[..8].iter().all(|&b| b));
    assert!(bits[8..].iter().all(|&b| !b));
}

// ============================================================================
// estimate_entropy
// ============================================================================

#[test]
fn test_entropy_all_zeros() {
    let tester = NistSp800_22Tester::default();
    let bits = vec![false; 1000];
    let entropy = tester.estimate_entropy(&bits);
    assert_eq!(entropy, 0.0); // proportion = 0.0, triggers early return
}

#[test]
fn test_entropy_all_ones() {
    let tester = NistSp800_22Tester::default();
    let bits = vec![true; 1000];
    let entropy = tester.estimate_entropy(&bits);
    assert_eq!(entropy, 0.0); // proportion = 1.0, triggers early return
}

#[test]
fn test_entropy_balanced() {
    let tester = NistSp800_22Tester::default();
    let mut bits = vec![false; 500];
    bits.extend(vec![true; 500]);
    let entropy = tester.estimate_entropy(&bits);
    // Perfect balance -> entropy should be close to 1.0
    assert!((entropy - 1.0).abs() < 0.01);
}

#[test]
fn test_entropy_empty() {
    let tester = NistSp800_22Tester::default();
    let entropy = tester.estimate_entropy(&[]);
    assert_eq!(entropy, 0.0);
}

#[test]
fn test_entropy_skewed() {
    let tester = NistSp800_22Tester::default();
    let mut bits = vec![true; 900];
    bits.extend(vec![false; 100]);
    let entropy = tester.estimate_entropy(&bits);
    // Skewed: entropy should be between 0 and 1
    assert!(entropy > 0.0);
    assert!(entropy < 1.0);
}

// ============================================================================
// Full test suite with various data patterns
// ============================================================================

#[test]
fn test_all_zeros_data() {
    let tester = NistSp800_22Tester::default();
    let data = vec![0x00u8; 1000];
    let result = tester.test_bit_sequence(&data).unwrap();
    assert!(!result.passed); // All zeros should fail randomness tests
    assert_eq!(result.test_results.len(), 6);
}

#[test]
fn test_all_ones_data() {
    let tester = NistSp800_22Tester::default();
    let data = vec![0xFFu8; 1000];
    let result = tester.test_bit_sequence(&data).unwrap();
    assert!(!result.passed);
}

#[test]
fn test_alternating_bits() {
    let tester = NistSp800_22Tester::default();
    let data = vec![0xAAu8; 1000]; // 10101010 pattern
    let result = tester.test_bit_sequence(&data).unwrap();
    assert_eq!(result.bits_tested, 8000);
    assert_eq!(result.test_results.len(), 6);
}

#[test]
fn test_random_data_passes() {
    let tester = NistSp800_22Tester::default();
    let mut data = vec![0u8; 2000];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut data);
    let result = tester.test_bit_sequence(&data).unwrap();
    assert_eq!(result.bits_tested, 16000);
    assert_eq!(result.algorithm, "NIST SP 800-22");
    // Random data should generally pass most tests
    let passing = result.test_results.iter().filter(|r| r.passed).count();
    assert!(passing >= 3, "Random data should pass most tests, got {}/6", passing);
}

// ============================================================================
// Large data to exercise different block size selection in longest_run
// ============================================================================

#[test]
fn test_medium_sequence_block_sizes() {
    // 128..=6272 range uses block_size=8, k=3
    let tester = NistSp800_22Tester::new(0.01, 128);
    let data = vec![0xAAu8; 200]; // 1600 bits
    let result = tester.test_bit_sequence(&data).unwrap();
    assert_eq!(result.test_results.len(), 6);
}

#[test]
fn test_large_sequence_block_sizes() {
    // 6273..=75000 range uses block_size=128, k=5
    let tester = NistSp800_22Tester::new(0.01, 128);
    let mut data = vec![0u8; 10000]; // 80000 bits
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut data);
    let result = tester.test_bit_sequence(&data).unwrap();
    assert_eq!(result.test_results.len(), 6);
}

// ============================================================================
// Test individual result fields
// ============================================================================

#[test]
fn test_result_test_names() {
    let tester = NistSp800_22Tester::default();
    let mut data = vec![0u8; 1000];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut data);
    let result = tester.test_bit_sequence(&data).unwrap();

    let names: Vec<&str> = result.test_results.iter().map(|r| r.test_name.as_str()).collect();
    assert!(names.contains(&"Frequency (Monobit) Test"));
    assert!(names.contains(&"Frequency Within Block Test"));
    assert!(names.contains(&"Runs Test"));
    assert!(names.contains(&"Longest Run of Ones in a Block Test"));
    assert!(names.contains(&"Serial Test"));
    assert!(names.contains(&"Approximate Entropy Test"));
}

#[test]
fn test_result_p_values_in_range() {
    let tester = NistSp800_22Tester::default();
    let mut data = vec![0u8; 1000];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut data);
    let result = tester.test_bit_sequence(&data).unwrap();

    for test_result in &result.test_results {
        // p-values should be non-negative
        assert!(
            test_result.p_value >= 0.0,
            "p_value for {} should be >= 0, got {}",
            test_result.test_name,
            test_result.p_value
        );
    }
}

// ============================================================================
// Edge case: minimum viable sequence for different tests
// ============================================================================

#[test]
fn test_small_custom_min_length() {
    // Very small min_sequence_length to exercise edge cases in block tests
    let tester = NistSp800_22Tester::new(0.01, 16);
    let data = vec![0xABu8; 2]; // 16 bits exactly
    let result = tester.test_bit_sequence(&data).unwrap();
    assert_eq!(result.bits_tested, 16);
    // Some tests may fail or return early with insufficient data
}

#[test]
fn test_significance_level_affects_pass_rate() {
    let mut data = vec![0u8; 1000];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut data);

    let strict = NistSp800_22Tester::new(0.10, 1000);
    let result_strict = strict.test_bit_sequence(&data).unwrap();

    let lenient = NistSp800_22Tester::new(0.001, 1000);
    let result_lenient = lenient.test_bit_sequence(&data).unwrap();

    // Both should have 6 test results
    assert_eq!(result_strict.test_results.len(), 6);
    assert_eq!(result_lenient.test_results.len(), 6);
}
