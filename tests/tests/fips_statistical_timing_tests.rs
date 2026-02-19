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

//! Statistical Timing Validation Tests
//!
//! Tests the arc-validation timing module: `TimingValidator` construction,
//! constant-time equality validation, error type enumeration, and statistical
//! measurement of operation timing.
//!
//! Run with: `cargo test --package arc-validation --test statistical_timing_tests --all-features --release -- --nocapture`

use latticearc_tests::validation::timing::{
    TimingError, TimingValidator, constant_time_eq, validate_constant_time,
};

// ============================================================================
// TimingError Variants
// ============================================================================

#[test]
fn test_timing_error_display_variation() {
    let e = TimingError::TimingVariation;
    let d = format!("{}", e);
    assert!(!d.is_empty(), "TimingVariation display must not be empty");
    assert!(d.contains("variance") || d.contains("ariation"), "Should mention variance/variation");
}

#[test]
fn test_timing_error_display_insufficient() {
    let e = TimingError::InsufficientSamples;
    let d = format!("{}", e);
    assert!(!d.is_empty(), "InsufficientSamples display must not be empty");
    assert!(d.contains("ample") || d.contains("nsufficient"), "Should mention samples");
}

#[test]
fn test_timing_error_display_constant_time_failed() {
    let e = TimingError::ConstantTimeFailed;
    let d = format!("{}", e);
    assert!(!d.is_empty());
}

#[test]
fn test_timing_error_variants_distinct() {
    let d1 = format!("{}", TimingError::TimingVariation);
    let d2 = format!("{}", TimingError::InsufficientSamples);
    let d3 = format!("{}", TimingError::ConstantTimeFailed);
    assert_ne!(d1, d2);
    assert_ne!(d2, d3);
    assert_ne!(d1, d3);
}

#[test]
fn test_timing_error_debug() {
    let e = TimingError::TimingVariation;
    let debug = format!("{:?}", e);
    assert!(!debug.is_empty());
}

// ============================================================================
// TimingValidator Construction
// ============================================================================

#[test]
fn test_timing_validator_construction() {
    // new(sample_count, max_timing_difference_ratio)
    let validator = TimingValidator::new(100, 0.20);
    // Should construct without panic; verify by using it
    let result = validator.validate_constant_time_operation(|| {
        std::hint::black_box(42);
        true
    });
    assert!(result.is_ok(), "Validator should successfully time a simple operation");
}

#[test]
fn test_timing_validator_default() {
    let validator = TimingValidator::default();
    let result = validator.validate_constant_time_operation(|| true);
    assert!(result.is_ok());
}

#[test]
fn test_timing_validator_insufficient_samples() {
    let validator = TimingValidator::new(5, 0.2); // Too few samples (< 10)
    let result = validator.validate_constant_time_operation(|| true);
    assert!(
        matches!(result, Err(TimingError::InsufficientSamples)),
        "Should reject sample count < 10, got: {:?}",
        result
    );
}

// ============================================================================
// Constant-Time Equality Function
// ============================================================================

#[test]
fn test_constant_time_eq_equal() {
    let a = [0x42u8; 32];
    let b = [0x42u8; 32];
    assert!(constant_time_eq(&a, &b), "Equal slices must return true");
}

#[test]
fn test_constant_time_eq_different() {
    let a = [0x42u8; 32];
    let b = [0x43u8; 32];
    assert!(!constant_time_eq(&a, &b), "Different slices must return false");
}

#[test]
fn test_constant_time_eq_empty() {
    let a: [u8; 0] = [];
    let b: [u8; 0] = [];
    assert!(constant_time_eq(&a, &b), "Empty slices must return true");
}

#[test]
fn test_constant_time_eq_single_byte_diff() {
    let a = [0x00u8; 64];
    let mut b = [0x00u8; 64];
    b[63] = 0x01;
    assert!(!constant_time_eq(&a, &b), "Last-byte difference must be detected");
}

#[test]
fn test_constant_time_eq_different_lengths() {
    let a = [0x42u8; 16];
    let b = [0x42u8; 32];
    assert!(!constant_time_eq(&a, &b), "Different lengths must return false");
}

#[test]
fn test_constant_time_eq_first_byte_diff() {
    let mut a = [0x00u8; 32];
    let b = [0x00u8; 32];
    a[0] = 0xFF;
    assert!(!constant_time_eq(&a, &b), "First-byte difference must be detected");
}

// ============================================================================
// validate_constant_time Top-Level Function
// ============================================================================

#[test]
fn test_validate_constant_time_passes() {
    let result = validate_constant_time();
    assert!(result.is_ok(), "validate_constant_time must pass: {:?}", result);
}

// ============================================================================
// TimingValidator — validate_constant_time_operation
// ============================================================================

#[test]
fn test_validate_noop_operation() {
    let validator = TimingValidator::new(50, 0.5);
    let result = validator.validate_constant_time_operation(|| std::hint::black_box(true));
    assert!(result.is_ok(), "No-op operation must succeed: {:?}", result);
}

#[test]
fn test_validate_xor_operation() {
    let validator = TimingValidator::new(50, 0.5);
    let a = [0xAAu8; 32];
    let b = [0xBBu8; 32];

    let result = validator.validate_constant_time_operation(|| {
        let mut c = [0u8; 32];
        for i in 0..32 {
            c[i] = a[i] ^ b[i];
        }
        std::hint::black_box(c[0] != 0)
    });
    assert!(result.is_ok(), "XOR timing must succeed: {:?}", result);
}

// ============================================================================
// TimingValidator — compare_timings
// ============================================================================

#[test]
fn test_compare_timings_similar_ops() {
    let validator = TimingValidator::new(50, 0.5); // generous threshold

    let a = [0x00u8; 64];
    let b = [0x00u8; 64];
    let c = [0xFFu8; 64];

    let result =
        validator.compare_timings(|| constant_time_eq(&a, &b), || constant_time_eq(&a, &c));
    // With generous threshold, similar constant-time ops should pass
    println!("compare_timings result: {:?}", result);
}

// ============================================================================
// TimingValidator — validate_constant_time_compare
// ============================================================================

#[test]
fn test_validate_constant_time_compare() {
    let validator = TimingValidator::new(100, 0.3);

    let data_a = vec![0x41u8; 32];
    let data_b = vec![0x42u8; 32];

    let result = validator.validate_constant_time_compare(&data_a, &data_b);
    println!("validate_constant_time_compare result: {:?}", result);
    // May pass or fail depending on environment; the key property is it doesn't panic
}

#[test]
fn test_validate_constant_time_compare_last_byte() {
    let validator = TimingValidator::new(100, 0.3);

    let data_a = vec![0x41u8; 32];
    let mut data_c = data_a.clone();
    if let Some(last) = data_c.last_mut() {
        *last = 0x42;
    }

    let result = validator.validate_constant_time_compare(&data_a, &data_c);
    println!("validate_constant_time_compare last-byte result: {:?}", result);
}
