//! Tests for format validation module
//!
//! This module tests key format validation functions.

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

use arc_validation::format::{FormatError, validate_key_format};

#[test]
fn test_validate_key_format_correct_size() {
    let key = vec![0u8; 32];
    let result = validate_key_format(&key, 32);
    assert!(result.is_ok());
}

#[test]
fn test_validate_key_format_wrong_size_too_small() {
    let key = vec![0u8; 16];
    let result = validate_key_format(&key, 32);
    assert!(result.is_err());

    match result.unwrap_err() {
        FormatError::InvalidKeySize(actual, expected) => {
            assert_eq!(actual, 16);
            assert_eq!(expected, 32);
        }
    }
}

#[test]
fn test_validate_key_format_wrong_size_too_large() {
    let key = vec![0u8; 64];
    let result = validate_key_format(&key, 32);
    assert!(result.is_err());

    match result.unwrap_err() {
        FormatError::InvalidKeySize(actual, expected) => {
            assert_eq!(actual, 64);
            assert_eq!(expected, 32);
        }
    }
}

#[test]
fn test_validate_key_format_empty_key() {
    let key: Vec<u8> = vec![];
    let result = validate_key_format(&key, 32);
    assert!(result.is_err());

    match result.unwrap_err() {
        FormatError::InvalidKeySize(actual, expected) => {
            assert_eq!(actual, 0);
            assert_eq!(expected, 32);
        }
    }
}

#[test]
fn test_validate_key_format_empty_expected() {
    let key: Vec<u8> = vec![];
    let result = validate_key_format(&key, 0);
    assert!(result.is_ok());
}

#[test]
fn test_validate_key_format_various_sizes() {
    // Test common key sizes
    let sizes = [16, 24, 32, 48, 64, 128, 256];

    for size in sizes {
        let key = vec![0x42u8; size];
        let result = validate_key_format(&key, size);
        assert!(result.is_ok(), "Key size {} should be valid", size);
    }
}

#[test]
fn test_format_error_display() {
    let error = FormatError::InvalidKeySize(16, 32);
    let display = format!("{}", error);
    assert!(display.contains("16"));
    assert!(display.contains("32"));
    assert!(display.contains("Invalid key size"));
}

#[test]
fn test_format_error_debug() {
    let error = FormatError::InvalidKeySize(16, 32);
    let debug = format!("{:?}", error);
    assert!(debug.contains("InvalidKeySize"));
}
