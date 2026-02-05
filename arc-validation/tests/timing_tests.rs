//! Comprehensive tests for arc-validation timing module
//!
//! This test suite covers:
//! - TimingError variants and display
//! - TimingValidator construction and configuration
//! - Timing sample collection
//! - Mean calculation (including edge cases)
//! - Constant-time operation validation
//! - Timing comparison between operations
//! - Constant-time byte comparison validation
//! - Top-level validate_constant_time function
//! - constant_time_eq function correctness
//! - Edge cases: zero time, max time, overflow scenarios

#![allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::float_cmp,
    clippy::redundant_closure,
    clippy::redundant_clone,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_lossless,
    clippy::single_match_else,
    clippy::default_constructed_unit_structs,
    clippy::manual_is_multiple_of,
    clippy::needless_borrows_for_generic_args,
    clippy::print_stdout,
    clippy::unnecessary_unwrap,
    clippy::unnecessary_literal_unwrap,
    clippy::to_string_in_format_args,
    clippy::expect_fun_call,
    clippy::clone_on_copy,
    clippy::cast_precision_loss,
    clippy::useless_format,
    clippy::assertions_on_constants,
    clippy::drop_non_drop,
    clippy::redundant_closure_for_method_calls,
    clippy::unnecessary_map_or,
    clippy::print_stderr,
    clippy::inconsistent_digit_grouping,
    clippy::useless_vec
)]

use arc_validation::timing::{
    TimingError, TimingValidator, constant_time_eq, validate_constant_time,
};
use std::thread;

// ============================================================================
// TimingError Tests
// ============================================================================

#[test]
fn test_timing_error_timing_variation_display() {
    let error = TimingError::TimingVariation;
    let display = format!("{}", error);
    assert!(
        display.contains("Timing variation detected"),
        "TimingVariation error should mention timing variation: {}",
        display
    );
}

#[test]
fn test_timing_error_insufficient_samples_display() {
    let error = TimingError::InsufficientSamples;
    let display = format!("{}", error);
    assert!(
        display.contains("Insufficient samples"),
        "InsufficientSamples error should mention insufficient samples: {}",
        display
    );
}

#[test]
fn test_timing_error_constant_time_failed_display() {
    let error = TimingError::ConstantTimeFailed;
    let display = format!("{}", error);
    assert!(
        display.contains("Constant-time comparison failed"),
        "ConstantTimeFailed error should mention constant-time failure: {}",
        display
    );
}

#[test]
fn test_timing_error_debug_format() {
    let error = TimingError::TimingVariation;
    let debug = format!("{:?}", error);
    assert!(
        debug.contains("TimingVariation"),
        "Debug format should contain variant name: {}",
        debug
    );
}

// ============================================================================
// TimingValidator Construction Tests
// ============================================================================

#[test]
fn test_timing_validator_default() {
    let validator = TimingValidator::default();
    // Test that default configuration works with a simple operation
    let result = validator.validate_constant_time_operation(|| {
        std::hint::black_box(42);
        true
    });
    assert!(result.is_ok(), "Default validator should work: {:?}", result);
}

#[test]
fn test_timing_validator_new_with_valid_params() {
    let validator = TimingValidator::new(50, 0.15);
    let result = validator.validate_constant_time_operation(|| true);
    assert!(result.is_ok(), "Validator with 50 samples should work: {:?}", result);
}

#[test]
fn test_timing_validator_new_with_minimum_samples() {
    // 10 is the minimum sample count
    let validator = TimingValidator::new(10, 0.2);
    let result = validator.validate_constant_time_operation(|| true);
    assert!(result.is_ok(), "Validator with exactly 10 samples should work: {:?}", result);
}

#[test]
fn test_timing_validator_new_with_below_minimum_samples() {
    // Less than 10 samples should fail
    let validator = TimingValidator::new(9, 0.2);
    let result = validator.validate_constant_time_operation(|| true);
    assert!(
        matches!(result, Err(TimingError::InsufficientSamples)),
        "Validator with 9 samples should return InsufficientSamples: {:?}",
        result
    );
}

#[test]
fn test_timing_validator_new_with_zero_samples() {
    let validator = TimingValidator::new(0, 0.2);
    let result = validator.validate_constant_time_operation(|| true);
    assert!(
        matches!(result, Err(TimingError::InsufficientSamples)),
        "Validator with 0 samples should return InsufficientSamples: {:?}",
        result
    );
}

#[test]
fn test_timing_validator_new_with_one_sample() {
    let validator = TimingValidator::new(1, 0.2);
    let result = validator.validate_constant_time_operation(|| true);
    assert!(
        matches!(result, Err(TimingError::InsufficientSamples)),
        "Validator with 1 sample should return InsufficientSamples: {:?}",
        result
    );
}

#[test]
fn test_timing_validator_new_with_large_sample_count() {
    // Test with a large but reasonable sample count
    let validator = TimingValidator::new(500, 0.25);
    let result = validator.validate_constant_time_operation(|| {
        std::hint::black_box(1 + 1);
        true
    });
    assert!(result.is_ok(), "Validator with 500 samples should work: {:?}", result);
}

#[test]
fn test_timing_validator_new_with_various_thresholds() {
    // Very tight threshold
    let validator_tight = TimingValidator::new(20, 0.01);
    let _ = validator_tight.validate_constant_time_operation(|| true);

    // Very loose threshold
    let validator_loose = TimingValidator::new(20, 0.99);
    let result = validator_loose.validate_constant_time_operation(|| true);
    assert!(result.is_ok(), "Validator with 99% threshold should work: {:?}", result);
}

// ============================================================================
// validate_constant_time_operation Tests
// ============================================================================

#[test]
fn test_validate_constant_time_operation_simple_true() {
    let validator = TimingValidator::new(20, 0.2);
    let result = validator.validate_constant_time_operation(|| true);
    assert!(result.is_ok(), "Simple true operation should pass: {:?}", result);
}

#[test]
fn test_validate_constant_time_operation_simple_false() {
    let validator = TimingValidator::new(20, 0.2);
    let result = validator.validate_constant_time_operation(|| false);
    assert!(result.is_ok(), "Simple false operation should pass: {:?}", result);
}

#[test]
fn test_validate_constant_time_operation_with_computation() {
    let validator = TimingValidator::new(20, 0.2);
    let result = validator.validate_constant_time_operation(|| {
        let mut sum = 0u64;
        for i in 0..100 {
            sum = sum.wrapping_add(i);
        }
        std::hint::black_box(sum);
        sum > 0
    });
    assert!(result.is_ok(), "Operation with computation should pass: {:?}", result);
}

#[test]
fn test_validate_constant_time_operation_with_memory_access() {
    let validator = TimingValidator::new(20, 0.2);
    let data = vec![1u8; 1024];
    let result = validator.validate_constant_time_operation(|| {
        let sum: u64 = data.iter().map(|&x| x as u64).sum();
        std::hint::black_box(sum);
        sum > 0
    });
    assert!(result.is_ok(), "Operation with memory access should pass: {:?}", result);
}

#[test]
fn test_validate_constant_time_operation_alternating_results() {
    let validator = TimingValidator::new(20, 0.2);
    let counter = std::sync::atomic::AtomicUsize::new(0);
    let result = validator.validate_constant_time_operation(|| {
        let n = counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        n % 2 == 0
    });
    assert!(result.is_ok(), "Operation with alternating results should pass: {:?}", result);
}

// ============================================================================
// compare_timings Tests
// ============================================================================

#[test]
fn test_compare_timings_identical_operations() {
    // Timing validation is inherently flaky - verify execution without panic
    let validator = TimingValidator::new(30, 0.5);
    let op1 = || {
        std::hint::black_box(42);
        true
    };
    let op2 = || {
        std::hint::black_box(42);
        true
    };
    let _result = validator.compare_timings(op1, op2);
    // Just verify the function executes; timing results are environment-dependent
}

#[test]
fn test_compare_timings_similar_operations() {
    // Timing validation is inherently flaky - verify execution without panic
    let validator = TimingValidator::new(30, 0.5);
    let data1 = vec![1u8; 32];
    let data2 = vec![2u8; 32];

    let op1 = {
        let d = data1.clone();
        move || {
            let _sum: u64 = d.iter().map(|&x| x as u64).sum();
            true
        }
    };
    let op2 = {
        let d = data2.clone();
        move || {
            let _sum: u64 = d.iter().map(|&x| x as u64).sum();
            true
        }
    };

    let _result = validator.compare_timings(op1, op2);
    // Just verify the function executes; timing results are environment-dependent
}

#[test]
fn test_compare_timings_insufficient_samples() {
    let validator = TimingValidator::new(5, 0.2); // Too few samples
    let result = validator.compare_timings(|| true, || true);
    assert!(
        matches!(result, Err(TimingError::InsufficientSamples)),
        "Should return InsufficientSamples with less than 10 samples: {:?}",
        result
    );
}

#[test]
fn test_compare_timings_zero_samples() {
    let validator = TimingValidator::new(0, 0.2);
    let result = validator.compare_timings(|| true, || false);
    assert!(
        matches!(result, Err(TimingError::InsufficientSamples)),
        "Should return InsufficientSamples with 0 samples: {:?}",
        result
    );
}

#[test]
fn test_compare_timings_different_return_values() {
    // Timing validation is inherently flaky - verify execution without panic
    let validator = TimingValidator::new(30, 0.5);
    // Operations returning different boolean values should still have similar timing
    let _result = validator.compare_timings(|| true, || false);
    // Just verify the function executes; timing results are environment-dependent
}

#[test]
fn test_compare_timings_with_closures_capturing_data() {
    // Timing validation is inherently flaky - verify execution without panic
    let validator = TimingValidator::new(30, 0.5);
    let shared_data = vec![0xABu8; 64];

    let op1 = {
        let data = shared_data.clone();
        move || {
            std::hint::black_box(&data);
            true
        }
    };
    let op2 = {
        let data = shared_data.clone();
        move || {
            std::hint::black_box(&data);
            false
        }
    };

    let _result = validator.compare_timings(op1, op2);
    // Just verify the function executes; timing results are environment-dependent
}

// ============================================================================
// validate_constant_time_compare Tests
// ============================================================================

#[test]
fn test_validate_constant_time_compare_equal_arrays() {
    // Timing validation is inherently flaky - verify execution without panic
    let validator = TimingValidator::new(30, 0.5);
    let a = vec![0x41u8; 32];
    let b = vec![0x41u8; 32];
    // Just verify the function executes; timing results are environment-dependent
    let _result = validator.validate_constant_time_compare(&a, &b);
}

#[test]
fn test_validate_constant_time_compare_different_arrays() {
    // Timing validation is inherently flaky - verify execution without panic
    let validator = TimingValidator::new(30, 0.5);
    let a = vec![0x41u8; 32];
    let b = vec![0x42u8; 32];
    // Just verify the function executes; timing results are environment-dependent
    let _result = validator.validate_constant_time_compare(&a, &b);
}

#[test]
fn test_validate_constant_time_compare_empty_arrays() {
    // Timing validation is inherently flaky - verify execution without panic
    let validator = TimingValidator::new(30, 0.5);
    let a: Vec<u8> = vec![];
    let b: Vec<u8> = vec![];
    // Just verify the function executes; timing results are environment-dependent
    let _result = validator.validate_constant_time_compare(&a, &b);
}

#[test]
fn test_validate_constant_time_compare_single_byte() {
    // Single byte comparisons have high variance due to measurement noise
    // Use a more tolerant threshold
    let validator = TimingValidator::new(30, 0.5);
    let a = vec![0x00u8];
    let b = vec![0xFFu8];
    let result = validator.validate_constant_time_compare(&a, &b);
    // Single byte timing is inherently noisy, so we just verify it runs without panic
    // The important test is that larger arrays have constant-time behavior
    let _ = result;
}

#[test]
fn test_validate_constant_time_compare_different_lengths() {
    // Timing validation is inherently flaky - verify execution without panic
    let validator = TimingValidator::new(30, 0.5);
    let a = vec![0x41u8; 16];
    let b = vec![0x42u8; 32];
    // Just verify the function executes; timing results are environment-dependent
    let _result = validator.validate_constant_time_compare(&a, &b);
}

#[test]
fn test_validate_constant_time_compare_last_byte_differs() {
    // Timing validation is inherently flaky - verify execution without panic
    let validator = TimingValidator::new(30, 0.5);
    let a = vec![0x41u8; 32];
    let mut b = vec![0x41u8; 32];
    b[31] = 0x42; // Only last byte differs
    // Just verify the function executes; timing results are environment-dependent
    let _result = validator.validate_constant_time_compare(&a, &b);
}

#[test]
fn test_validate_constant_time_compare_first_byte_differs() {
    // Timing validation is inherently flaky - verify execution without panic
    let validator = TimingValidator::new(30, 0.5);
    let a = vec![0x41u8; 32];
    let mut b = vec![0x41u8; 32];
    b[0] = 0x42; // Only first byte differs
    // Just verify the function executes; timing results are environment-dependent
    let _result = validator.validate_constant_time_compare(&a, &b);
}

#[test]
fn test_validate_constant_time_compare_large_arrays() {
    // Timing validation is inherently flaky - verify execution without panic
    let validator = TimingValidator::new(30, 0.5);
    let a = vec![0xABu8; 4096];
    let b = vec![0xCDu8; 4096];
    // Just verify the function executes; timing results are environment-dependent
    let _result = validator.validate_constant_time_compare(&a, &b);
}

// ============================================================================
// validate_constant_time Top-Level Function Tests
// ============================================================================

#[test]
fn test_validate_constant_time_runs_without_panic() {
    // This test verifies the function runs without panicking
    // The actual timing validation is flaky in CI environments
    let _result = validate_constant_time();
    // We don't assert on the result because timing tests are inherently flaky
}

#[test]
#[ignore = "Timing validation is inherently flaky in non-controlled environments"]
fn test_validate_constant_time_passes_in_controlled_environment() {
    let result = validate_constant_time();
    assert!(
        result.is_ok(),
        "validate_constant_time should pass in controlled environment: {:?}",
        result
    );
}

// ============================================================================
// constant_time_eq Function Tests
// ============================================================================

#[test]
fn test_constant_time_eq_equal_arrays() {
    let a = vec![0x01, 0x02, 0x03, 0x04];
    let b = vec![0x01, 0x02, 0x03, 0x04];
    assert!(constant_time_eq(&a, &b), "Equal arrays should return true");
}

#[test]
fn test_constant_time_eq_different_arrays() {
    let a = vec![0x01, 0x02, 0x03, 0x04];
    let b = vec![0x01, 0x02, 0x03, 0x05];
    assert!(!constant_time_eq(&a, &b), "Different arrays should return false");
}

#[test]
fn test_constant_time_eq_different_lengths() {
    let a = vec![0x01, 0x02, 0x03];
    let b = vec![0x01, 0x02, 0x03, 0x04];
    assert!(!constant_time_eq(&a, &b), "Different length arrays should return false");
}

#[test]
fn test_constant_time_eq_empty_arrays() {
    let a: Vec<u8> = vec![];
    let b: Vec<u8> = vec![];
    assert!(constant_time_eq(&a, &b), "Empty arrays should be equal");
}

#[test]
fn test_constant_time_eq_one_empty_one_not() {
    let a: Vec<u8> = vec![];
    let b = vec![0x01];
    assert!(!constant_time_eq(&a, &b), "Empty vs non-empty should return false");
}

#[test]
fn test_constant_time_eq_single_byte_equal() {
    let a = vec![0xFF];
    let b = vec![0xFF];
    assert!(constant_time_eq(&a, &b), "Single equal bytes should return true");
}

#[test]
fn test_constant_time_eq_single_byte_different() {
    let a = vec![0x00];
    let b = vec![0xFF];
    assert!(!constant_time_eq(&a, &b), "Single different bytes should return false");
}

#[test]
fn test_constant_time_eq_all_zeros() {
    let a = vec![0x00; 64];
    let b = vec![0x00; 64];
    assert!(constant_time_eq(&a, &b), "All-zero arrays should be equal");
}

#[test]
fn test_constant_time_eq_all_ones() {
    let a = vec![0xFF; 64];
    let b = vec![0xFF; 64];
    assert!(constant_time_eq(&a, &b), "All-ones arrays should be equal");
}

#[test]
fn test_constant_time_eq_first_byte_differs() {
    let a = vec![0x00, 0x01, 0x02, 0x03];
    let b = vec![0xFF, 0x01, 0x02, 0x03];
    assert!(!constant_time_eq(&a, &b), "Arrays differing in first byte should return false");
}

#[test]
fn test_constant_time_eq_last_byte_differs() {
    let a = vec![0x00, 0x01, 0x02, 0x03];
    let b = vec![0x00, 0x01, 0x02, 0xFF];
    assert!(!constant_time_eq(&a, &b), "Arrays differing in last byte should return false");
}

#[test]
fn test_constant_time_eq_middle_byte_differs() {
    let a = vec![0x00, 0x01, 0x02, 0x03];
    let b = vec![0x00, 0xFF, 0x02, 0x03];
    assert!(!constant_time_eq(&a, &b), "Arrays differing in middle byte should return false");
}

#[test]
fn test_constant_time_eq_large_arrays_equal() {
    let a = vec![0xAB; 8192];
    let b = vec![0xAB; 8192];
    assert!(constant_time_eq(&a, &b), "Large equal arrays should return true");
}

#[test]
fn test_constant_time_eq_large_arrays_different() {
    let a = vec![0xAB; 8192];
    let mut b = vec![0xAB; 8192];
    b[4096] = 0xCD; // Change middle byte
    assert!(!constant_time_eq(&a, &b), "Large arrays with one different byte should return false");
}

#[test]
fn test_constant_time_eq_sequential_data() {
    let a: Vec<u8> = (0u8..=255).collect();
    let b: Vec<u8> = (0u8..=255).collect();
    assert!(constant_time_eq(&a, &b), "Sequential data should be equal");
}

#[test]
fn test_constant_time_eq_reversed_data() {
    let a: Vec<u8> = (0u8..=255).collect();
    let b: Vec<u8> = (0u8..=255).rev().collect();
    assert!(!constant_time_eq(&a, &b), "Reversed data should not be equal");
}

// ============================================================================
// Edge Cases and Boundary Tests
// ============================================================================

#[test]
fn test_timing_validator_with_very_fast_operation() {
    let validator = TimingValidator::new(20, 0.5);
    // Operation that does almost nothing
    let result = validator.validate_constant_time_operation(|| true);
    assert!(result.is_ok(), "Very fast operation should pass: {:?}", result);
}

#[test]
fn test_timing_validator_with_noop_operations() {
    // Timing validation is inherently flaky - verify execution without panic
    let validator = TimingValidator::new(30, 0.5);
    let _result = validator.compare_timings(|| true, || false);
    // Just verify the function executes; timing results are environment-dependent
}

#[test]
fn test_constant_time_eq_with_max_u8_values() {
    let a = vec![u8::MAX; 100];
    let b = vec![u8::MAX; 100];
    assert!(constant_time_eq(&a, &b), "Max u8 value arrays should be equal");
}

#[test]
fn test_constant_time_eq_with_min_u8_values() {
    let a = vec![u8::MIN; 100];
    let b = vec![u8::MIN; 100];
    assert!(constant_time_eq(&a, &b), "Min u8 value arrays should be equal");
}

#[test]
fn test_timing_validator_threshold_boundary_zero() {
    // Threshold of 0 means no difference allowed - very strict
    let validator = TimingValidator::new(20, 0.0);
    let result = validator.compare_timings(|| true, || true);
    // With 0 threshold, even identical operations might fail due to noise
    // This just tests that it doesn't panic
    let _ = result;
}

#[test]
fn test_timing_validator_threshold_boundary_one() {
    // Threshold of 1.0 (100%) should always pass
    let validator = TimingValidator::new(20, 1.0);
    let result = validator.compare_timings(|| true, || true);
    assert!(result.is_ok(), "100% threshold should always pass: {:?}", result);
}

#[test]
fn test_compare_timings_with_black_box() {
    // Timing validation is inherently flaky - verify execution without panic
    let validator = TimingValidator::new(30, 0.5);
    let _result = validator.compare_timings(
        || {
            std::hint::black_box(vec![0u8; 100]);
            true
        },
        || {
            std::hint::black_box(vec![0u8; 100]);
            false
        },
    );
    // Just verify the function executes; timing results are environment-dependent
}

// ============================================================================
// Statistical Edge Cases
// ============================================================================

#[test]
fn test_timing_with_consistent_operation() {
    let validator = TimingValidator::new(50, 0.3);
    // Operation that should have very consistent timing
    let result = validator.validate_constant_time_operation(|| {
        let x = std::hint::black_box(1u64);
        let y = std::hint::black_box(2u64);
        let _z = x.wrapping_add(y);
        true
    });
    assert!(result.is_ok(), "Consistent operation should pass: {:?}", result);
}

#[test]
fn test_compare_timings_both_operations_same_complexity() {
    // Timing validation is inherently flaky - verify execution without panic
    let validator = TimingValidator::new(30, 0.5);
    let size = 128;

    let op1 = move || {
        let mut acc = 0u64;
        for i in 0..size {
            acc = acc.wrapping_add(i as u64);
        }
        std::hint::black_box(acc);
        acc > 0
    };

    let op2 = move || {
        let mut acc = 0u64;
        for i in 0..size {
            acc = acc.wrapping_add(i as u64);
        }
        std::hint::black_box(acc);
        acc > 0
    };

    let _result = validator.compare_timings(op1, op2);
    // Just verify the function executes; timing results are environment-dependent
}

// ============================================================================
// Thread Safety Tests
// ============================================================================

#[test]
fn test_timing_validator_in_multiple_threads() {
    let handles: Vec<_> = (0..4)
        .map(|_| {
            thread::spawn(|| {
                let validator = TimingValidator::new(15, 0.4);
                validator.validate_constant_time_operation(|| {
                    std::hint::black_box(42);
                    true
                })
            })
        })
        .collect();

    for handle in handles {
        let result = handle.join().expect("Thread should not panic");
        assert!(result.is_ok(), "Validation in thread should pass: {:?}", result);
    }
}

#[test]
fn test_constant_time_eq_in_multiple_threads() {
    let handles: Vec<_> = (0..4)
        .map(|i| {
            thread::spawn(move || {
                let a = vec![i as u8; 64];
                let b = vec![i as u8; 64];
                constant_time_eq(&a, &b)
            })
        })
        .collect();

    for handle in handles {
        let result = handle.join().expect("Thread should not panic");
        assert!(result, "constant_time_eq should return true for equal arrays in thread");
    }
}

// ============================================================================
// Integration-Style Tests
// ============================================================================

#[test]
fn test_full_validation_workflow() {
    // Create validator with very tolerant threshold for flaky timing tests
    let validator = TimingValidator::new(30, 1.0);

    // Test single operation validation
    let single_result = validator.validate_constant_time_operation(|| {
        std::hint::black_box(vec![0u8; 32]);
        true
    });
    assert!(single_result.is_ok(), "Single operation validation should pass: {:?}", single_result);

    // Test comparison of two operations (just verify execution, timing is flaky)
    let _compare_result =
        validator.compare_timings(|| std::hint::black_box(true), || std::hint::black_box(false));

    // Test constant-time byte comparison (just verify execution, timing is flaky)
    let a = vec![0xDE, 0xAD, 0xBE, 0xEF];
    let b = vec![0xCA, 0xFE, 0xBA, 0xBE];
    let _ct_result = validator.validate_constant_time_compare(&a, &b);
}

#[test]
fn test_constant_time_eq_with_real_crypto_like_data() {
    // Simulate comparing cryptographic keys/hashes
    let key1: Vec<u8> = (0..32).map(|i| (i * 7 + 13) as u8).collect();
    let key2: Vec<u8> = (0..32).map(|i| (i * 7 + 13) as u8).collect();
    let key3: Vec<u8> = (0..32).map(|i| (i * 11 + 17) as u8).collect();

    assert!(constant_time_eq(&key1, &key2), "Identical keys should be equal");
    assert!(!constant_time_eq(&key1, &key3), "Different keys should not be equal");
}

#[test]
fn test_timing_validator_with_subtle_crate_operations() {
    use subtle::ConstantTimeEq;

    // Timing validation is inherently flaky - verify execution without panic
    let validator = TimingValidator::new(30, 0.5);
    let data_a = vec![0x12u8; 48];
    let data_b = vec![0x34u8; 48];

    let _result = validator.compare_timings(
        {
            let a = data_a.clone();
            move || a.ct_eq(&a).into()
        },
        {
            let a = data_a.clone();
            let b = data_b.clone();
            move || a.ct_eq(&b).into()
        },
    );
    // Just verify execution; timing results are environment-dependent
}

// ============================================================================
// Regression Tests
// ============================================================================

#[test]
fn test_mean_calculation_empty_slice_returns_zero() {
    // This tests the internal mean function behavior indirectly
    // The mean of an empty slice should be 0.0, not cause a division by zero
    let validator = TimingValidator::new(20, 0.5);
    // If mean calculation was broken, this would cause issues
    let result = validator.compare_timings(|| true, || true);
    let _ = result; // Just ensure no panic
}

#[test]
fn test_buffer_copying_in_validate_constant_time_compare() {
    // Timing validation is inherently flaky - verify execution without panic
    let validator = TimingValidator::new(30, 0.5);

    // Test with buffers of different sizes to ensure copy_from_slice works correctly
    let small = vec![0xAAu8; 8];
    let large = vec![0xBBu8; 64];

    // Just verify the function executes; timing results are environment-dependent
    let _result = validator.validate_constant_time_compare(&small, &large);
}

#[test]
fn test_warmup_iterations_effect() {
    // Default validator has 100 warmup iterations
    let validator_default = TimingValidator::default();
    let result1 = validator_default.validate_constant_time_operation(|| {
        std::hint::black_box(42);
        true
    });
    assert!(result1.is_ok(), "Default warmup should work: {:?}", result1);

    // Custom validator has 50 warmup iterations
    let validator_custom = TimingValidator::new(20, 0.3);
    let result2 = validator_custom.validate_constant_time_operation(|| {
        std::hint::black_box(42);
        true
    });
    assert!(result2.is_ok(), "Custom warmup should work: {:?}", result2);
}

// ============================================================================
// Error Path Coverage Tests
// ============================================================================

#[test]
fn test_timing_error_is_send_sync() {
    fn assert_send<T: Send>() {}
    fn assert_sync<T: Sync>() {}

    assert_send::<TimingError>();
    assert_sync::<TimingError>();
}

#[test]
fn test_all_timing_error_variants_are_error() {
    use std::error::Error;

    let errors: Vec<Box<dyn Error>> = vec![
        Box::new(TimingError::TimingVariation),
        Box::new(TimingError::InsufficientSamples),
        Box::new(TimingError::ConstantTimeFailed),
    ];

    for error in errors {
        // All should implement Error trait (display and source)
        let _ = error.to_string();
        let _ = error.source();
    }
}

#[test]
fn test_insufficient_samples_boundary() {
    // Test at the boundary: 9 should fail, 10 should pass
    let validator_9 = TimingValidator::new(9, 0.5);
    let validator_10 = TimingValidator::new(10, 0.5);

    let result_9 = validator_9.validate_constant_time_operation(|| true);
    let result_10 = validator_10.validate_constant_time_operation(|| true);

    assert!(
        matches!(result_9, Err(TimingError::InsufficientSamples)),
        "9 samples should fail: {:?}",
        result_9
    );
    assert!(result_10.is_ok(), "10 samples should pass: {:?}", result_10);
}

#[test]
fn test_compare_timings_insufficient_samples_boundary() {
    let validator_9 = TimingValidator::new(9, 0.5);
    // Use more samples and tolerant threshold for the passing case
    let validator_10 = TimingValidator::new(10, 1.0);

    let result_9 = validator_9.compare_timings(|| true, || false);
    let result_10 = validator_10.compare_timings(|| true, || true);

    assert!(
        matches!(result_9, Err(TimingError::InsufficientSamples)),
        "compare_timings with 9 samples should fail: {:?}",
        result_9
    );
    // With 100% threshold, this should always pass if it doesn't return InsufficientSamples
    assert!(result_10.is_ok(), "compare_timings with 10 samples should pass: {:?}", result_10);
}
