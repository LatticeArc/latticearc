//! Comprehensive tests for arc-validation crate
//!
//! This test suite covers:
//! - Input validation (size, range)
//! - Output validation and bounds checking
//! - Format validation for cryptographic primitives
//! - Resource limits validation
//! - Timing-safe operations
//! - Error handling

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

use arc_validation::{
    FormatError,
    ResourceError,
    // Resource limits
    ResourceLimits,
    ResourceLimitsManager,
    ValidationError,
    get_global_resource_limits,
    validate_decryption_size,
    validate_encryption_size,
    // Input validation
    validate_input_size,
    validate_key_derivation_count,
    // Format validation
    validate_key_format,
    validate_signature_size,
};

// Import bounds module types with explicit paths
use arc_validation::bounds::{BoundsError, validate_bounds};
use arc_validation::output::{
    BoundsChecker, BoundsError as OutputBoundsError, OutputError, OutputValidator, SimpleValidator,
};

// ============================================================================
// Input Validation Tests
// ============================================================================

mod input_validation_tests {
    use super::*;

    #[test]
    fn test_validate_input_size_valid() {
        let input = vec![0u8; 32];
        assert!(validate_input_size(&input, 16, 64).is_ok());
    }

    #[test]
    fn test_validate_input_size_exact_min() {
        let input = vec![0u8; 16];
        assert!(validate_input_size(&input, 16, 64).is_ok());
    }

    #[test]
    fn test_validate_input_size_exact_max() {
        let input = vec![0u8; 64];
        assert!(validate_input_size(&input, 16, 64).is_ok());
    }

    #[test]
    fn test_validate_input_size_too_small() {
        let input = vec![0u8; 8];
        let result = validate_input_size(&input, 16, 64);
        assert!(result.is_err());
        match result.unwrap_err() {
            ValidationError::InputTooSmall(actual, min) => {
                assert_eq!(actual, 8);
                assert_eq!(min, 16);
            }
            _ => panic!("Expected InputTooSmall error"),
        }
    }

    #[test]
    fn test_validate_input_size_too_large() {
        let input = vec![0u8; 128];
        let result = validate_input_size(&input, 16, 64);
        assert!(result.is_err());
        match result.unwrap_err() {
            ValidationError::InputTooLarge(actual, max) => {
                assert_eq!(actual, 128);
                assert_eq!(max, 64);
            }
            _ => panic!("Expected InputTooLarge error"),
        }
    }

    #[test]
    fn test_validate_input_size_empty_input() {
        let input = vec![];
        assert!(validate_input_size(&input, 0, 64).is_ok());
        assert!(validate_input_size(&input, 1, 64).is_err());
    }

    #[test]
    fn test_validate_input_size_zero_max() {
        let input = vec![];
        assert!(validate_input_size(&input, 0, 0).is_ok());
    }

    #[test]
    fn test_validation_error_display() {
        let err = ValidationError::InputTooSmall(10, 20);
        let msg = format!("{}", err);
        assert!(msg.contains("10"));
        assert!(msg.contains("20"));
    }

    #[test]
    fn test_validation_error_debug() {
        let err = ValidationError::InputTooLarge(100, 50);
        let debug = format!("{:?}", err);
        assert!(debug.contains("InputTooLarge"));
    }
}

// ============================================================================
// Bounds Validation Tests
// ============================================================================

mod bounds_validation_tests {
    use super::*;

    #[test]
    fn test_validate_bounds_valid() {
        assert!(validate_bounds(50, 0, 100).is_ok());
    }

    #[test]
    fn test_validate_bounds_exact_min() {
        assert!(validate_bounds(0, 0, 100).is_ok());
    }

    #[test]
    fn test_validate_bounds_exact_max() {
        assert!(validate_bounds(100, 0, 100).is_ok());
    }

    #[test]
    fn test_validate_bounds_too_small() {
        let result = validate_bounds(5, 10, 100);
        assert!(result.is_err());
        match result.unwrap_err() {
            BoundsError::ValueTooSmall(value, min) => {
                assert_eq!(value, 5);
                assert_eq!(min, 10);
            }
            _ => panic!("Expected ValueTooSmall error"),
        }
    }

    #[test]
    fn test_validate_bounds_too_large() {
        let result = validate_bounds(150, 10, 100);
        assert!(result.is_err());
        match result.unwrap_err() {
            BoundsError::ValueTooLarge(value, max) => {
                assert_eq!(value, 150);
                assert_eq!(max, 100);
            }
            _ => panic!("Expected ValueTooLarge error"),
        }
    }

    #[test]
    fn test_validate_bounds_equal_min_max() {
        assert!(validate_bounds(42, 42, 42).is_ok());
        assert!(validate_bounds(41, 42, 42).is_err());
        assert!(validate_bounds(43, 42, 42).is_err());
    }

    #[test]
    fn test_bounds_error_display() {
        let err = BoundsError::ValueTooSmall(5, 10);
        let msg = format!("{}", err);
        assert!(msg.contains("5"));
        assert!(msg.contains("10"));
    }
}

// ============================================================================
// Format Validation Tests
// ============================================================================

mod format_validation_tests {
    use super::*;

    #[test]
    fn test_validate_key_format_valid() {
        let key = vec![0u8; 32];
        assert!(validate_key_format(&key, 32).is_ok());
    }

    #[test]
    fn test_validate_key_format_invalid_size() {
        let key = vec![0u8; 24];
        let result = validate_key_format(&key, 32);
        assert!(result.is_err());
        match result.unwrap_err() {
            FormatError::InvalidKeySize(actual, expected) => {
                assert_eq!(actual, 24);
                assert_eq!(expected, 32);
            }
        }
    }

    #[test]
    fn test_validate_key_format_aes_128() {
        let key = vec![0u8; 16];
        assert!(validate_key_format(&key, 16).is_ok());
    }

    #[test]
    fn test_validate_key_format_aes_256() {
        let key = vec![0u8; 32];
        assert!(validate_key_format(&key, 32).is_ok());
    }

    #[test]
    fn test_validate_key_format_empty() {
        let key = vec![];
        assert!(validate_key_format(&key, 0).is_ok());
        assert!(validate_key_format(&key, 1).is_err());
    }

    #[test]
    fn test_format_error_display() {
        let err = FormatError::InvalidKeySize(16, 32);
        let msg = format!("{}", err);
        assert!(msg.contains("16"));
        assert!(msg.contains("32"));
    }
}

// ============================================================================
// Resource Limits Tests
// ============================================================================

mod resource_limits_tests {
    use super::*;

    #[test]
    fn test_resource_limits_default() {
        let limits = ResourceLimits::default();
        assert_eq!(limits.max_key_derivations_per_call, 1000);
        assert_eq!(limits.max_encryption_size_bytes, 100 * 1024 * 1024);
        assert_eq!(limits.max_signature_size_bytes, 64 * 1024);
        assert_eq!(limits.max_decryption_size_bytes, 100 * 1024 * 1024);
    }

    #[test]
    fn test_resource_limits_new() {
        let limits = ResourceLimits::new(500, 50 * 1024 * 1024, 32 * 1024, 50 * 1024 * 1024);
        assert_eq!(limits.max_key_derivations_per_call, 500);
        assert_eq!(limits.max_encryption_size_bytes, 50 * 1024 * 1024);
        assert_eq!(limits.max_signature_size_bytes, 32 * 1024);
        assert_eq!(limits.max_decryption_size_bytes, 50 * 1024 * 1024);
    }

    #[test]
    fn test_validate_key_derivation_count_valid() {
        assert!(ResourceLimits::validate_key_derivation_count(100).is_ok());
    }

    #[test]
    fn test_validate_key_derivation_count_exceeded() {
        let result = ResourceLimits::validate_key_derivation_count(2000);
        assert!(result.is_err());
        match result.unwrap_err() {
            ResourceError::KeyDerivationLimitExceeded { requested, limit } => {
                assert_eq!(requested, 2000);
                assert_eq!(limit, 1000);
            }
            _ => panic!("Expected KeyDerivationLimitExceeded error"),
        }
    }

    #[test]
    fn test_validate_encryption_size_valid() {
        assert!(ResourceLimits::validate_encryption_size(1024 * 1024).is_ok());
    }

    #[test]
    fn test_validate_encryption_size_exceeded() {
        let result = ResourceLimits::validate_encryption_size(200 * 1024 * 1024);
        assert!(result.is_err());
        match result.unwrap_err() {
            ResourceError::EncryptionSizeLimitExceeded { requested, limit } => {
                assert_eq!(requested, 200 * 1024 * 1024);
                assert_eq!(limit, 100 * 1024 * 1024);
            }
            _ => panic!("Expected EncryptionSizeLimitExceeded error"),
        }
    }

    #[test]
    fn test_validate_signature_size_valid() {
        assert!(ResourceLimits::validate_signature_size(1024).is_ok());
    }

    #[test]
    fn test_validate_signature_size_exceeded() {
        let result = ResourceLimits::validate_signature_size(100 * 1024);
        assert!(result.is_err());
        match result.unwrap_err() {
            ResourceError::SignatureSizeLimitExceeded { requested, limit } => {
                assert_eq!(requested, 100 * 1024);
                assert_eq!(limit, 64 * 1024);
            }
            _ => panic!("Expected SignatureSizeLimitExceeded error"),
        }
    }

    #[test]
    fn test_validate_decryption_size_valid() {
        assert!(ResourceLimits::validate_decryption_size(1024 * 1024).is_ok());
    }

    #[test]
    fn test_validate_decryption_size_exceeded() {
        let result = ResourceLimits::validate_decryption_size(200 * 1024 * 1024);
        assert!(result.is_err());
        match result.unwrap_err() {
            ResourceError::DecryptionSizeLimitExceeded { requested, limit } => {
                assert_eq!(requested, 200 * 1024 * 1024);
                assert_eq!(limit, 100 * 1024 * 1024);
            }
            _ => panic!("Expected DecryptionSizeLimitExceeded error"),
        }
    }
}

// ============================================================================
// Resource Limits Manager Tests
// ============================================================================

mod resource_limits_manager_tests {
    use super::*;

    #[test]
    fn test_resource_limits_manager_new() {
        let manager = ResourceLimitsManager::new();
        let limits = manager.get_limits();
        assert_eq!(limits.max_key_derivations_per_call, 1000);
    }

    #[test]
    fn test_resource_limits_manager_with_limits() {
        let custom_limits = ResourceLimits::new(500, 25 * 1024 * 1024, 16 * 1024, 25 * 1024 * 1024);
        let manager = ResourceLimitsManager::with_limits(custom_limits);
        let limits = manager.get_limits();
        assert_eq!(limits.max_key_derivations_per_call, 500);
        assert_eq!(limits.max_encryption_size_bytes, 25 * 1024 * 1024);
    }

    #[test]
    fn test_resource_limits_manager_update() {
        let manager = ResourceLimitsManager::new();
        let new_limits = ResourceLimits::new(200, 10 * 1024 * 1024, 8 * 1024, 10 * 1024 * 1024);
        manager.update_limits(new_limits);
        let limits = manager.get_limits();
        assert_eq!(limits.max_key_derivations_per_call, 200);
    }

    #[test]
    fn test_resource_limits_manager_validate_key_derivation() {
        let manager = ResourceLimitsManager::new();
        assert!(manager.validate_key_derivation_count(100).is_ok());
        assert!(manager.validate_key_derivation_count(2000).is_err());
    }

    #[test]
    fn test_resource_limits_manager_validate_encryption() {
        let manager = ResourceLimitsManager::new();
        assert!(manager.validate_encryption_size(1024 * 1024).is_ok());
        assert!(manager.validate_encryption_size(200 * 1024 * 1024).is_err());
    }

    #[test]
    fn test_resource_limits_manager_validate_signature() {
        let manager = ResourceLimitsManager::new();
        assert!(manager.validate_signature_size(1024).is_ok());
        assert!(manager.validate_signature_size(100 * 1024).is_err());
    }

    #[test]
    fn test_resource_limits_manager_validate_decryption() {
        let manager = ResourceLimitsManager::new();
        assert!(manager.validate_decryption_size(1024 * 1024).is_ok());
        assert!(manager.validate_decryption_size(200 * 1024 * 1024).is_err());
    }

    #[test]
    fn test_resource_limits_manager_default() {
        let manager = ResourceLimitsManager::default();
        let limits = manager.get_limits();
        assert_eq!(limits.max_key_derivations_per_call, 1000);
    }
}

// ============================================================================
// Global Resource Limits Tests
// ============================================================================

mod global_resource_limits_tests {
    use super::*;

    #[test]
    fn test_get_global_resource_limits() {
        let manager = get_global_resource_limits();
        let limits = manager.get_limits();
        assert!(limits.max_key_derivations_per_call > 0);
    }

    #[test]
    fn test_global_validate_key_derivation_count() {
        assert!(validate_key_derivation_count(100).is_ok());
    }

    #[test]
    fn test_global_validate_encryption_size() {
        assert!(validate_encryption_size(1024 * 1024).is_ok());
    }

    #[test]
    fn test_global_validate_signature_size() {
        assert!(validate_signature_size(1024).is_ok());
    }

    #[test]
    fn test_global_validate_decryption_size() {
        assert!(validate_decryption_size(1024 * 1024).is_ok());
    }
}

// ============================================================================
// Resource Error Tests
// ============================================================================

mod resource_error_tests {
    use super::*;

    #[test]
    fn test_resource_error_key_derivation_display() {
        let err = ResourceError::KeyDerivationLimitExceeded { requested: 2000, limit: 1000 };
        let msg = format!("{}", err);
        assert!(msg.contains("2000"));
        assert!(msg.contains("1000"));
        assert!(msg.contains("Key derivation"));
    }

    #[test]
    fn test_resource_error_encryption_display() {
        let err = ResourceError::EncryptionSizeLimitExceeded {
            requested: 200 * 1024 * 1024,
            limit: 100 * 1024 * 1024,
        };
        let msg = format!("{}", err);
        assert!(msg.contains("Encryption"));
    }

    #[test]
    fn test_resource_error_signature_display() {
        let err =
            ResourceError::SignatureSizeLimitExceeded { requested: 100 * 1024, limit: 64 * 1024 };
        let msg = format!("{}", err);
        assert!(msg.contains("Signature"));
    }

    #[test]
    fn test_resource_error_decryption_display() {
        let err = ResourceError::DecryptionSizeLimitExceeded {
            requested: 200 * 1024 * 1024,
            limit: 100 * 1024 * 1024,
        };
        let msg = format!("{}", err);
        assert!(msg.contains("Decryption"));
    }

    #[test]
    fn test_resource_error_debug() {
        let err = ResourceError::KeyDerivationLimitExceeded { requested: 2000, limit: 1000 };
        let debug = format!("{:?}", err);
        assert!(debug.contains("KeyDerivationLimitExceeded"));
    }
}

// ============================================================================
// Edge Case Tests
// ============================================================================

mod edge_case_tests {
    use super::*;

    #[test]
    fn test_zero_values() {
        // Zero-length input
        let empty = vec![];
        assert!(validate_input_size(&empty, 0, 0).is_ok());

        // Zero bounds
        assert!(validate_bounds(0, 0, 0).is_ok());

        // Zero key size
        assert!(validate_key_format(&[], 0).is_ok());
    }

    #[test]
    fn test_max_values() {
        // Large values within limits
        assert!(validate_bounds(usize::MAX - 1, 0, usize::MAX).is_ok());
    }

    #[test]
    fn test_boundary_conditions() {
        // Exact boundary tests
        let input = vec![0u8; 100];
        assert!(validate_input_size(&input, 100, 100).is_ok());
        assert!(validate_input_size(&input, 101, 200).is_err());
        assert!(validate_input_size(&input, 0, 99).is_err());
    }
}

// ============================================================================
// Concurrent Access Tests
// ============================================================================

mod concurrent_tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn test_resource_limits_manager_concurrent_read() {
        let manager = Arc::new(ResourceLimitsManager::new());
        let mut handles = vec![];

        for _ in 0..10 {
            let manager_clone = Arc::clone(&manager);
            handles.push(thread::spawn(move || {
                for _ in 0..100 {
                    let limits = manager_clone.get_limits();
                    assert!(limits.max_key_derivations_per_call > 0);
                }
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }
    }

    #[test]
    fn test_resource_limits_manager_concurrent_validation() {
        let manager = Arc::new(ResourceLimitsManager::new());
        let mut handles = vec![];

        for _ in 0..10 {
            let manager_clone = Arc::clone(&manager);
            handles.push(thread::spawn(move || {
                for i in 0..100 {
                    let _ = manager_clone.validate_key_derivation_count(i);
                    let _ = manager_clone.validate_encryption_size(i * 1024);
                    let _ = manager_clone.validate_signature_size(i * 10);
                }
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }
    }
}

// ============================================================================
// Property-Based Tests
// ============================================================================

mod property_tests {
    use super::*;

    #[test]
    fn test_input_validation_symmetry() {
        // If min == max, only exact size is valid
        for size in [16, 32, 64, 128] {
            let input = vec![0u8; size];
            assert!(validate_input_size(&input, size, size).is_ok());

            let smaller = vec![0u8; size - 1];
            assert!(validate_input_size(&smaller, size, size).is_err());

            let larger = vec![0u8; size + 1];
            assert!(validate_input_size(&larger, size, size).is_err());
        }
    }

    #[test]
    fn test_bounds_validation_ordering() {
        // Values within bounds are always valid
        for (min, max) in [(0, 100), (10, 50), (100, 1000)] {
            for value in (min..=max).step_by(std::cmp::max(1, (max - min) / 10)) {
                assert!(validate_bounds(value, min, max).is_ok());
            }
        }
    }

    #[test]
    fn test_key_format_sizes() {
        // Common cryptographic key sizes
        for size in [16, 24, 32, 48, 64] {
            let key = vec![0u8; size];
            assert!(validate_key_format(&key, size).is_ok());
            assert!(validate_key_format(&key, size + 1).is_err());
            if size > 0 {
                assert!(validate_key_format(&key, size - 1).is_err());
            }
        }
    }
}

// ============================================================================
// Integration Tests
// ============================================================================

mod integration_tests {
    use super::*;

    #[test]
    fn test_combined_validation_workflow() {
        // Simulate a typical cryptographic operation validation workflow

        // 1. Validate input data size
        let plaintext = vec![0u8; 1024];
        assert!(validate_input_size(&plaintext, 1, 10 * 1024 * 1024).is_ok());

        // 2. Validate key format
        let key = vec![0u8; 32];
        assert!(validate_key_format(&key, 32).is_ok());

        // 3. Validate resource limits
        assert!(validate_encryption_size(plaintext.len()).is_ok());

        // 4. Validate output bounds
        let expected_output_size = plaintext.len() + 16; // Add authentication tag
        assert!(validate_bounds(expected_output_size, 0, 100 * 1024 * 1024).is_ok());
    }

    #[test]
    fn test_signature_validation_workflow() {
        // Validate signature operation
        let message = vec![0u8; 512];
        let signature_key = vec![0u8; 32];

        // Validate inputs
        assert!(validate_input_size(&message, 0, 1024 * 1024).is_ok());
        assert!(validate_key_format(&signature_key, 32).is_ok());

        // Validate signature size limit
        let signature_size = 64;
        assert!(validate_signature_size(signature_size).is_ok());
    }

    #[test]
    fn test_custom_limits_manager() {
        // Create manager with restricted limits
        let restricted_limits = ResourceLimits::new(
            10,          // max 10 key derivations
            1024 * 1024, // max 1MB encryption
            4096,        // max 4KB signatures
            1024 * 1024, // max 1MB decryption
        );
        let manager = ResourceLimitsManager::with_limits(restricted_limits);

        // These should fail with restricted limits
        assert!(manager.validate_key_derivation_count(20).is_err());
        assert!(manager.validate_encryption_size(2 * 1024 * 1024).is_err());
        assert!(manager.validate_signature_size(8192).is_err());
        assert!(manager.validate_decryption_size(2 * 1024 * 1024).is_err());

        // These should pass
        assert!(manager.validate_key_derivation_count(5).is_ok());
        assert!(manager.validate_encryption_size(512 * 1024).is_ok());
        assert!(manager.validate_signature_size(2048).is_ok());
        assert!(manager.validate_decryption_size(512 * 1024).is_ok());
    }
}

// ============================================================================
// Output Validation Tests
// ============================================================================

mod output_validation_tests {
    use super::*;

    #[test]
    fn test_simple_validator_new() {
        let validator = SimpleValidator::new();
        let output = vec![0u8; 32];
        assert!(validator.validate_output(&output).is_ok());
    }

    #[test]
    fn test_simple_validator_default() {
        let validator = SimpleValidator::default();
        let output = vec![0u8; 32];
        assert!(validator.validate_output(&output).is_ok());
    }

    #[test]
    fn test_output_validator_empty() {
        let validator = SimpleValidator::new();
        let output = vec![];
        let result = validator.validate_output(&output);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), OutputError::EmptyOutput));
    }

    #[test]
    fn test_output_validator_too_large() {
        let validator = SimpleValidator::new();
        // Create output larger than 10MB limit
        let output = vec![0u8; 11 * 1024 * 1024];
        let result = validator.validate_output(&output);
        assert!(result.is_err());
        match result.unwrap_err() {
            OutputError::OutputTooLarge { size, max } => {
                assert_eq!(size, 11 * 1024 * 1024);
                assert_eq!(max, 10 * 1024 * 1024);
            }
            _ => panic!("Expected OutputTooLarge error"),
        }
    }

    #[test]
    fn test_output_validator_invalid_byte() {
        let validator = SimpleValidator::new();
        // 0xFF is considered invalid in SimpleValidator
        let output = vec![0u8, 0x10, 0xFF, 0x20];
        let result = validator.validate_output(&output);
        assert!(result.is_err());
        match result.unwrap_err() {
            OutputError::InvalidByte { position, byte } => {
                assert_eq!(position, 2);
                assert_eq!(byte, 0xFF);
            }
            _ => panic!("Expected InvalidByte error"),
        }
    }

    #[test]
    fn test_bounds_checker_valid() {
        let validator = SimpleValidator::new();
        let value = vec![0u8; 32];
        assert!(validator.check_bounds(&value, 16, 64).is_ok());
    }

    #[test]
    fn test_bounds_checker_exact_min() {
        let validator = SimpleValidator::new();
        let value = vec![0u8; 16];
        assert!(validator.check_bounds(&value, 16, 64).is_ok());
    }

    #[test]
    fn test_bounds_checker_exact_max() {
        let validator = SimpleValidator::new();
        let value = vec![0u8; 64];
        assert!(validator.check_bounds(&value, 16, 64).is_ok());
    }

    #[test]
    fn test_bounds_checker_out_of_bounds() {
        let validator = SimpleValidator::new();
        let value = vec![0u8; 8];
        let result = validator.check_bounds(&value, 16, 64);
        assert!(result.is_err());
        match result.unwrap_err() {
            OutputBoundsError::OutOfBounds { actual, min, max } => {
                assert_eq!(actual, 8);
                assert_eq!(min, 16);
                assert_eq!(max, 64);
            }
            _ => panic!("Expected OutOfBounds error"),
        }
    }

    #[test]
    fn test_bounds_checker_invalid_bounds() {
        let validator = SimpleValidator::new();
        let value = vec![0u8; 32];
        // min > max is invalid
        let result = validator.check_bounds(&value, 100, 50);
        assert!(result.is_err());
        match result.unwrap_err() {
            OutputBoundsError::InvalidBounds { min, max } => {
                assert_eq!(min, 100);
                assert_eq!(max, 50);
            }
            _ => panic!("Expected InvalidBounds error"),
        }
    }

    #[test]
    fn test_output_error_display() {
        let err = OutputError::EmptyOutput;
        let msg = format!("{}", err);
        assert!(msg.contains("empty"));

        let err = OutputError::InvalidLength("test".to_string());
        let msg = format!("{}", err);
        assert!(msg.contains("Invalid"));

        let err = OutputError::InvalidByte { position: 5, byte: 0xAB };
        let msg = format!("{}", err);
        assert!(msg.contains("5"));
        assert!(msg.contains("ab") || msg.contains("AB"));

        let err = OutputError::OutputTooLarge { size: 100, max: 50 };
        let msg = format!("{}", err);
        assert!(msg.contains("100"));
        assert!(msg.contains("50"));
    }

    #[test]
    fn test_output_bounds_error_display() {
        let err = OutputBoundsError::OutOfBounds { actual: 10, min: 20, max: 30 };
        let msg = format!("{}", err);
        assert!(msg.contains("10"));
        assert!(msg.contains("20"));
        assert!(msg.contains("30"));

        let err = OutputBoundsError::InvalidBounds { min: 100, max: 50 };
        let msg = format!("{}", err);
        assert!(msg.contains("100"));
        assert!(msg.contains("50"));
    }
}
