#![deny(unsafe_code)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::panic)]
#![allow(clippy::indexing_slicing)]
#![allow(missing_docs)]

//! Coverage tests for input.rs — validate_input_size and ValidationError

use arc_validation::input::{ValidationError, validate_input_size};

// ============================================================================
// validate_input_size — valid inputs
// ============================================================================

#[test]
fn test_valid_input_exact_min() {
    let data = vec![0u8; 16];
    assert!(validate_input_size(&data, 16, 64).is_ok());
}

#[test]
fn test_valid_input_exact_max() {
    let data = vec![0u8; 64];
    assert!(validate_input_size(&data, 16, 64).is_ok());
}

#[test]
fn test_valid_input_between() {
    let data = vec![0u8; 32];
    assert!(validate_input_size(&data, 16, 64).is_ok());
}

#[test]
fn test_valid_input_zero_min() {
    let data = vec![];
    assert!(validate_input_size(&data, 0, 100).is_ok());
}

#[test]
fn test_valid_input_min_equals_max() {
    let data = vec![0u8; 32];
    assert!(validate_input_size(&data, 32, 32).is_ok());
}

// ============================================================================
// validate_input_size — InputTooSmall
// ============================================================================

#[test]
fn test_input_too_small() {
    let data = vec![0u8; 15];
    let result = validate_input_size(&data, 16, 64);
    assert!(result.is_err());
    match result.unwrap_err() {
        ValidationError::InputTooSmall(actual, min) => {
            assert_eq!(actual, 15);
            assert_eq!(min, 16);
        }
        other => panic!("Expected InputTooSmall, got {:?}", other),
    }
}

#[test]
fn test_input_too_small_empty() {
    let data = vec![];
    let result = validate_input_size(&data, 1, 100);
    assert!(result.is_err());
    match result.unwrap_err() {
        ValidationError::InputTooSmall(actual, min) => {
            assert_eq!(actual, 0);
            assert_eq!(min, 1);
        }
        other => panic!("Expected InputTooSmall, got {:?}", other),
    }
}

// ============================================================================
// validate_input_size — InputTooLarge
// ============================================================================

#[test]
fn test_input_too_large() {
    let data = vec![0u8; 65];
    let result = validate_input_size(&data, 16, 64);
    assert!(result.is_err());
    match result.unwrap_err() {
        ValidationError::InputTooLarge(actual, max) => {
            assert_eq!(actual, 65);
            assert_eq!(max, 64);
        }
        other => panic!("Expected InputTooLarge, got {:?}", other),
    }
}

#[test]
fn test_input_too_large_by_one() {
    let data = vec![0u8; 33];
    let result = validate_input_size(&data, 0, 32);
    assert!(result.is_err());
    match result.unwrap_err() {
        ValidationError::InputTooLarge(actual, max) => {
            assert_eq!(actual, 33);
            assert_eq!(max, 32);
        }
        other => panic!("Expected InputTooLarge, got {:?}", other),
    }
}

// ============================================================================
// ValidationError Display
// ============================================================================

#[test]
fn test_validation_error_display_too_small() {
    let err = ValidationError::InputTooSmall(10, 16);
    let msg = format!("{}", err);
    assert!(msg.contains("too small"));
    assert!(msg.contains("10"));
    assert!(msg.contains("16"));
}

#[test]
fn test_validation_error_display_too_large() {
    let err = ValidationError::InputTooLarge(100, 64);
    let msg = format!("{}", err);
    assert!(msg.contains("too large"));
    assert!(msg.contains("100"));
    assert!(msg.contains("64"));
}

#[test]
fn test_validation_error_debug() {
    let err = ValidationError::InputTooSmall(5, 10);
    let debug = format!("{:?}", err);
    assert!(debug.contains("InputTooSmall"));
}
