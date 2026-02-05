//! Comprehensive tests for resource_limits module
//!
//! This test suite aims to achieve 80%+ code coverage for resource_limits.rs
//! by testing all public functions, methods, error paths, and edge cases.

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

use arc_validation::resource_limits::{
    ResourceError, ResourceLimits, ResourceLimitsManager, get_global_resource_limits,
    validate_decryption_size, validate_encryption_size, validate_key_derivation_count,
    validate_signature_size,
};

// ============================================================================
// ResourceLimits Struct Tests
// ============================================================================

mod resource_limits_struct_tests {
    use super::*;

    #[test]
    fn test_default_creates_expected_values() {
        let limits = ResourceLimits::default();
        assert_eq!(limits.max_key_derivations_per_call, 1000);
        assert_eq!(limits.max_encryption_size_bytes, 100 * 1024 * 1024);
        assert_eq!(limits.max_signature_size_bytes, 64 * 1024);
        assert_eq!(limits.max_decryption_size_bytes, 100 * 1024 * 1024);
    }

    #[test]
    fn test_new_with_custom_values() {
        let limits = ResourceLimits::new(500, 50 * 1024 * 1024, 32 * 1024, 25 * 1024 * 1024);
        assert_eq!(limits.max_key_derivations_per_call, 500);
        assert_eq!(limits.max_encryption_size_bytes, 50 * 1024 * 1024);
        assert_eq!(limits.max_signature_size_bytes, 32 * 1024);
        assert_eq!(limits.max_decryption_size_bytes, 25 * 1024 * 1024);
    }

    #[test]
    fn test_new_with_zero_values() {
        let limits = ResourceLimits::new(0, 0, 0, 0);
        assert_eq!(limits.max_key_derivations_per_call, 0);
        assert_eq!(limits.max_encryption_size_bytes, 0);
        assert_eq!(limits.max_signature_size_bytes, 0);
        assert_eq!(limits.max_decryption_size_bytes, 0);
    }

    #[test]
    fn test_new_with_max_values() {
        let limits = ResourceLimits::new(usize::MAX, usize::MAX, usize::MAX, usize::MAX);
        assert_eq!(limits.max_key_derivations_per_call, usize::MAX);
        assert_eq!(limits.max_encryption_size_bytes, usize::MAX);
        assert_eq!(limits.max_signature_size_bytes, usize::MAX);
        assert_eq!(limits.max_decryption_size_bytes, usize::MAX);
    }

    #[test]
    fn test_clone_trait() {
        let original = ResourceLimits::new(100, 200, 300, 400);
        let cloned = original.clone();
        assert_eq!(cloned.max_key_derivations_per_call, 100);
        assert_eq!(cloned.max_encryption_size_bytes, 200);
        assert_eq!(cloned.max_signature_size_bytes, 300);
        assert_eq!(cloned.max_decryption_size_bytes, 400);
    }

    #[test]
    fn test_debug_trait() {
        let limits = ResourceLimits::default();
        let debug_str = format!("{:?}", limits);
        assert!(debug_str.contains("ResourceLimits"));
        assert!(debug_str.contains("max_key_derivations_per_call"));
        assert!(debug_str.contains("1000"));
    }
}

// ============================================================================
// ResourceLimits Static Validation Method Tests
// ============================================================================

mod resource_limits_static_validation_tests {
    use super::*;

    // Key Derivation Count Tests
    #[test]
    fn test_validate_key_derivation_count_zero() {
        assert!(ResourceLimits::validate_key_derivation_count(0).is_ok());
    }

    #[test]
    fn test_validate_key_derivation_count_one() {
        assert!(ResourceLimits::validate_key_derivation_count(1).is_ok());
    }

    #[test]
    fn test_validate_key_derivation_count_at_limit() {
        assert!(ResourceLimits::validate_key_derivation_count(1000).is_ok());
    }

    #[test]
    fn test_validate_key_derivation_count_just_over_limit() {
        let result = ResourceLimits::validate_key_derivation_count(1001);
        assert!(result.is_err());
        match result.unwrap_err() {
            ResourceError::KeyDerivationLimitExceeded { requested, limit } => {
                assert_eq!(requested, 1001);
                assert_eq!(limit, 1000);
            }
            _ => panic!("Expected KeyDerivationLimitExceeded error"),
        }
    }

    #[test]
    fn test_validate_key_derivation_count_way_over_limit() {
        let result = ResourceLimits::validate_key_derivation_count(usize::MAX);
        assert!(result.is_err());
    }

    // Encryption Size Tests
    #[test]
    fn test_validate_encryption_size_zero() {
        assert!(ResourceLimits::validate_encryption_size(0).is_ok());
    }

    #[test]
    fn test_validate_encryption_size_one() {
        assert!(ResourceLimits::validate_encryption_size(1).is_ok());
    }

    #[test]
    fn test_validate_encryption_size_at_limit() {
        assert!(ResourceLimits::validate_encryption_size(100 * 1024 * 1024).is_ok());
    }

    #[test]
    fn test_validate_encryption_size_just_over_limit() {
        let limit = 100 * 1024 * 1024;
        let result = ResourceLimits::validate_encryption_size(limit + 1);
        assert!(result.is_err());
        match result.unwrap_err() {
            ResourceError::EncryptionSizeLimitExceeded { requested, limit: l } => {
                assert_eq!(requested, limit + 1);
                assert_eq!(l, limit);
            }
            _ => panic!("Expected EncryptionSizeLimitExceeded error"),
        }
    }

    // Signature Size Tests
    #[test]
    fn test_validate_signature_size_zero() {
        assert!(ResourceLimits::validate_signature_size(0).is_ok());
    }

    #[test]
    fn test_validate_signature_size_one() {
        assert!(ResourceLimits::validate_signature_size(1).is_ok());
    }

    #[test]
    fn test_validate_signature_size_at_limit() {
        assert!(ResourceLimits::validate_signature_size(64 * 1024).is_ok());
    }

    #[test]
    fn test_validate_signature_size_just_over_limit() {
        let limit = 64 * 1024;
        let result = ResourceLimits::validate_signature_size(limit + 1);
        assert!(result.is_err());
        match result.unwrap_err() {
            ResourceError::SignatureSizeLimitExceeded { requested, limit: l } => {
                assert_eq!(requested, limit + 1);
                assert_eq!(l, limit);
            }
            _ => panic!("Expected SignatureSizeLimitExceeded error"),
        }
    }

    // Decryption Size Tests
    #[test]
    fn test_validate_decryption_size_zero() {
        assert!(ResourceLimits::validate_decryption_size(0).is_ok());
    }

    #[test]
    fn test_validate_decryption_size_one() {
        assert!(ResourceLimits::validate_decryption_size(1).is_ok());
    }

    #[test]
    fn test_validate_decryption_size_at_limit() {
        assert!(ResourceLimits::validate_decryption_size(100 * 1024 * 1024).is_ok());
    }

    #[test]
    fn test_validate_decryption_size_just_over_limit() {
        let limit = 100 * 1024 * 1024;
        let result = ResourceLimits::validate_decryption_size(limit + 1);
        assert!(result.is_err());
        match result.unwrap_err() {
            ResourceError::DecryptionSizeLimitExceeded { requested, limit: l } => {
                assert_eq!(requested, limit + 1);
                assert_eq!(l, limit);
            }
            _ => panic!("Expected DecryptionSizeLimitExceeded error"),
        }
    }
}

// ============================================================================
// ResourceLimitsManager Tests
// ============================================================================

mod resource_limits_manager_tests {
    use super::*;

    #[test]
    fn test_new_creates_default_limits() {
        let manager = ResourceLimitsManager::new();
        let limits = manager.get_limits();
        assert_eq!(limits.max_key_derivations_per_call, 1000);
        assert_eq!(limits.max_encryption_size_bytes, 100 * 1024 * 1024);
    }

    #[test]
    fn test_with_limits_custom_values() {
        let custom_limits = ResourceLimits::new(50, 1024, 512, 2048);
        let manager = ResourceLimitsManager::with_limits(custom_limits);
        let limits = manager.get_limits();
        assert_eq!(limits.max_key_derivations_per_call, 50);
        assert_eq!(limits.max_encryption_size_bytes, 1024);
        assert_eq!(limits.max_signature_size_bytes, 512);
        assert_eq!(limits.max_decryption_size_bytes, 2048);
    }

    #[test]
    fn test_update_limits() {
        let manager = ResourceLimitsManager::new();
        let new_limits = ResourceLimits::new(25, 512, 256, 1024);
        manager.update_limits(new_limits);
        let limits = manager.get_limits();
        assert_eq!(limits.max_key_derivations_per_call, 25);
        assert_eq!(limits.max_encryption_size_bytes, 512);
    }

    #[test]
    fn test_default_trait() {
        let manager = ResourceLimitsManager::default();
        let limits = manager.get_limits();
        assert_eq!(limits.max_key_derivations_per_call, 1000);
    }

    // Manager Validation Tests - Success Cases
    #[test]
    fn test_manager_validate_key_derivation_count_valid() {
        let manager = ResourceLimitsManager::new();
        assert!(manager.validate_key_derivation_count(0).is_ok());
        assert!(manager.validate_key_derivation_count(500).is_ok());
        assert!(manager.validate_key_derivation_count(1000).is_ok());
    }

    #[test]
    fn test_manager_validate_encryption_size_valid() {
        let manager = ResourceLimitsManager::new();
        assert!(manager.validate_encryption_size(0).is_ok());
        assert!(manager.validate_encryption_size(50 * 1024 * 1024).is_ok());
        assert!(manager.validate_encryption_size(100 * 1024 * 1024).is_ok());
    }

    #[test]
    fn test_manager_validate_signature_size_valid() {
        let manager = ResourceLimitsManager::new();
        assert!(manager.validate_signature_size(0).is_ok());
        assert!(manager.validate_signature_size(32 * 1024).is_ok());
        assert!(manager.validate_signature_size(64 * 1024).is_ok());
    }

    #[test]
    fn test_manager_validate_decryption_size_valid() {
        let manager = ResourceLimitsManager::new();
        assert!(manager.validate_decryption_size(0).is_ok());
        assert!(manager.validate_decryption_size(50 * 1024 * 1024).is_ok());
        assert!(manager.validate_decryption_size(100 * 1024 * 1024).is_ok());
    }

    // Manager Validation Tests - Error Cases
    #[test]
    fn test_manager_validate_key_derivation_count_exceeded() {
        let manager = ResourceLimitsManager::new();
        let result = manager.validate_key_derivation_count(1001);
        assert!(result.is_err());
        match result.unwrap_err() {
            ResourceError::KeyDerivationLimitExceeded { requested, limit } => {
                assert_eq!(requested, 1001);
                assert_eq!(limit, 1000);
            }
            _ => panic!("Expected KeyDerivationLimitExceeded error"),
        }
    }

    #[test]
    fn test_manager_validate_encryption_size_exceeded() {
        let manager = ResourceLimitsManager::new();
        let limit = 100 * 1024 * 1024;
        let result = manager.validate_encryption_size(limit + 1);
        assert!(result.is_err());
        match result.unwrap_err() {
            ResourceError::EncryptionSizeLimitExceeded { requested, limit: l } => {
                assert_eq!(requested, limit + 1);
                assert_eq!(l, limit);
            }
            _ => panic!("Expected EncryptionSizeLimitExceeded error"),
        }
    }

    #[test]
    fn test_manager_validate_signature_size_exceeded() {
        let manager = ResourceLimitsManager::new();
        let limit = 64 * 1024;
        let result = manager.validate_signature_size(limit + 1);
        assert!(result.is_err());
        match result.unwrap_err() {
            ResourceError::SignatureSizeLimitExceeded { requested, limit: l } => {
                assert_eq!(requested, limit + 1);
                assert_eq!(l, limit);
            }
            _ => panic!("Expected SignatureSizeLimitExceeded error"),
        }
    }

    #[test]
    fn test_manager_validate_decryption_size_exceeded() {
        let manager = ResourceLimitsManager::new();
        let limit = 100 * 1024 * 1024;
        let result = manager.validate_decryption_size(limit + 1);
        assert!(result.is_err());
        match result.unwrap_err() {
            ResourceError::DecryptionSizeLimitExceeded { requested, limit: l } => {
                assert_eq!(requested, limit + 1);
                assert_eq!(l, limit);
            }
            _ => panic!("Expected DecryptionSizeLimitExceeded error"),
        }
    }

    // Manager with Custom Limits Validation
    #[test]
    fn test_manager_with_custom_limits_validation() {
        let custom_limits = ResourceLimits::new(10, 100, 50, 200);
        let manager = ResourceLimitsManager::with_limits(custom_limits);

        // Valid within custom limits
        assert!(manager.validate_key_derivation_count(10).is_ok());
        assert!(manager.validate_encryption_size(100).is_ok());
        assert!(manager.validate_signature_size(50).is_ok());
        assert!(manager.validate_decryption_size(200).is_ok());

        // Exceeded custom limits
        assert!(manager.validate_key_derivation_count(11).is_err());
        assert!(manager.validate_encryption_size(101).is_err());
        assert!(manager.validate_signature_size(51).is_err());
        assert!(manager.validate_decryption_size(201).is_err());
    }

    #[test]
    fn test_manager_with_zero_limits() {
        let zero_limits = ResourceLimits::new(0, 0, 0, 0);
        let manager = ResourceLimitsManager::with_limits(zero_limits);

        // Only zero should be valid
        assert!(manager.validate_key_derivation_count(0).is_ok());
        assert!(manager.validate_encryption_size(0).is_ok());
        assert!(manager.validate_signature_size(0).is_ok());
        assert!(manager.validate_decryption_size(0).is_ok());

        // Anything above zero should fail
        assert!(manager.validate_key_derivation_count(1).is_err());
        assert!(manager.validate_encryption_size(1).is_err());
        assert!(manager.validate_signature_size(1).is_err());
        assert!(manager.validate_decryption_size(1).is_err());
    }
}

// ============================================================================
// Global Resource Limits Tests
// ============================================================================

mod global_resource_limits_tests {
    use super::*;

    #[test]
    fn test_get_global_resource_limits_returns_manager() {
        let manager = get_global_resource_limits();
        let limits = manager.get_limits();
        assert!(limits.max_key_derivations_per_call > 0);
    }

    #[test]
    fn test_get_global_resource_limits_same_instance() {
        let manager1 = get_global_resource_limits();
        let manager2 = get_global_resource_limits();
        // Both should return the same static reference
        let limits1 = manager1.get_limits();
        let limits2 = manager2.get_limits();
        assert_eq!(limits1.max_key_derivations_per_call, limits2.max_key_derivations_per_call);
    }

    // Global Validation Functions - Success Cases
    #[test]
    fn test_global_validate_key_derivation_count_valid() {
        assert!(validate_key_derivation_count(0).is_ok());
        assert!(validate_key_derivation_count(500).is_ok());
        assert!(validate_key_derivation_count(1000).is_ok());
    }

    #[test]
    fn test_global_validate_encryption_size_valid() {
        assert!(validate_encryption_size(0).is_ok());
        assert!(validate_encryption_size(50 * 1024 * 1024).is_ok());
        assert!(validate_encryption_size(100 * 1024 * 1024).is_ok());
    }

    #[test]
    fn test_global_validate_signature_size_valid() {
        assert!(validate_signature_size(0).is_ok());
        assert!(validate_signature_size(32 * 1024).is_ok());
        assert!(validate_signature_size(64 * 1024).is_ok());
    }

    #[test]
    fn test_global_validate_decryption_size_valid() {
        assert!(validate_decryption_size(0).is_ok());
        assert!(validate_decryption_size(50 * 1024 * 1024).is_ok());
        assert!(validate_decryption_size(100 * 1024 * 1024).is_ok());
    }

    // Global Validation Functions - Error Cases
    #[test]
    fn test_global_validate_key_derivation_count_exceeded() {
        let result = validate_key_derivation_count(1001);
        assert!(result.is_err());
        match result.unwrap_err() {
            ResourceError::KeyDerivationLimitExceeded { requested, limit } => {
                assert_eq!(requested, 1001);
                assert_eq!(limit, 1000);
            }
            _ => panic!("Expected KeyDerivationLimitExceeded error"),
        }
    }

    #[test]
    fn test_global_validate_encryption_size_exceeded() {
        let limit = 100 * 1024 * 1024;
        let result = validate_encryption_size(limit + 1);
        assert!(result.is_err());
        match result.unwrap_err() {
            ResourceError::EncryptionSizeLimitExceeded { requested, limit: l } => {
                assert_eq!(requested, limit + 1);
                assert_eq!(l, limit);
            }
            _ => panic!("Expected EncryptionSizeLimitExceeded error"),
        }
    }

    #[test]
    fn test_global_validate_signature_size_exceeded() {
        let limit = 64 * 1024;
        let result = validate_signature_size(limit + 1);
        assert!(result.is_err());
        match result.unwrap_err() {
            ResourceError::SignatureSizeLimitExceeded { requested, limit: l } => {
                assert_eq!(requested, limit + 1);
                assert_eq!(l, limit);
            }
            _ => panic!("Expected SignatureSizeLimitExceeded error"),
        }
    }

    #[test]
    fn test_global_validate_decryption_size_exceeded() {
        let limit = 100 * 1024 * 1024;
        let result = validate_decryption_size(limit + 1);
        assert!(result.is_err());
        match result.unwrap_err() {
            ResourceError::DecryptionSizeLimitExceeded { requested, limit: l } => {
                assert_eq!(requested, limit + 1);
                assert_eq!(l, limit);
            }
            _ => panic!("Expected DecryptionSizeLimitExceeded error"),
        }
    }

    // Global Validation Functions - Extreme Cases
    #[test]
    fn test_global_validate_key_derivation_count_max() {
        let result = validate_key_derivation_count(usize::MAX);
        assert!(result.is_err());
    }

    #[test]
    fn test_global_validate_encryption_size_max() {
        let result = validate_encryption_size(usize::MAX);
        assert!(result.is_err());
    }

    #[test]
    fn test_global_validate_signature_size_max() {
        let result = validate_signature_size(usize::MAX);
        assert!(result.is_err());
    }

    #[test]
    fn test_global_validate_decryption_size_max() {
        let result = validate_decryption_size(usize::MAX);
        assert!(result.is_err());
    }
}

// ============================================================================
// ResourceError Tests
// ============================================================================

mod resource_error_tests {
    use super::*;

    #[test]
    fn test_key_derivation_error_display() {
        let err = ResourceError::KeyDerivationLimitExceeded { requested: 2000, limit: 1000 };
        let msg = format!("{}", err);
        assert!(msg.contains("Key derivation"));
        assert!(msg.contains("2000"));
        assert!(msg.contains("1000"));
    }

    #[test]
    fn test_encryption_size_error_display() {
        let err = ResourceError::EncryptionSizeLimitExceeded {
            requested: 200 * 1024 * 1024,
            limit: 100 * 1024 * 1024,
        };
        let msg = format!("{}", err);
        assert!(msg.contains("Encryption size"));
    }

    #[test]
    fn test_signature_size_error_display() {
        let err =
            ResourceError::SignatureSizeLimitExceeded { requested: 100 * 1024, limit: 64 * 1024 };
        let msg = format!("{}", err);
        assert!(msg.contains("Signature size"));
    }

    #[test]
    fn test_decryption_size_error_display() {
        let err = ResourceError::DecryptionSizeLimitExceeded {
            requested: 200 * 1024 * 1024,
            limit: 100 * 1024 * 1024,
        };
        let msg = format!("{}", err);
        assert!(msg.contains("Decryption size"));
    }

    #[test]
    fn test_key_derivation_error_debug() {
        let err = ResourceError::KeyDerivationLimitExceeded { requested: 2000, limit: 1000 };
        let debug = format!("{:?}", err);
        assert!(debug.contains("KeyDerivationLimitExceeded"));
        assert!(debug.contains("2000"));
        assert!(debug.contains("1000"));
    }

    #[test]
    fn test_encryption_size_error_debug() {
        let err = ResourceError::EncryptionSizeLimitExceeded { requested: 200, limit: 100 };
        let debug = format!("{:?}", err);
        assert!(debug.contains("EncryptionSizeLimitExceeded"));
    }

    #[test]
    fn test_signature_size_error_debug() {
        let err = ResourceError::SignatureSizeLimitExceeded { requested: 100, limit: 50 };
        let debug = format!("{:?}", err);
        assert!(debug.contains("SignatureSizeLimitExceeded"));
    }

    #[test]
    fn test_decryption_size_error_debug() {
        let err = ResourceError::DecryptionSizeLimitExceeded { requested: 200, limit: 100 };
        let debug = format!("{:?}", err);
        assert!(debug.contains("DecryptionSizeLimitExceeded"));
    }

    #[test]
    fn test_error_is_std_error() {
        let err = ResourceError::KeyDerivationLimitExceeded { requested: 2000, limit: 1000 };
        // Verify it implements std::error::Error
        let _: &dyn std::error::Error = &err;
    }
}

// ============================================================================
// Edge Cases and Boundary Tests
// ============================================================================

mod edge_case_tests {
    use super::*;

    #[test]
    fn test_all_validations_at_exact_limits() {
        // Test that exact limit values are accepted
        assert!(ResourceLimits::validate_key_derivation_count(1000).is_ok());
        assert!(ResourceLimits::validate_encryption_size(100 * 1024 * 1024).is_ok());
        assert!(ResourceLimits::validate_signature_size(64 * 1024).is_ok());
        assert!(ResourceLimits::validate_decryption_size(100 * 1024 * 1024).is_ok());
    }

    #[test]
    fn test_all_validations_one_over_limits() {
        // Test that limit + 1 is rejected
        assert!(ResourceLimits::validate_key_derivation_count(1001).is_err());
        assert!(ResourceLimits::validate_encryption_size(100 * 1024 * 1024 + 1).is_err());
        assert!(ResourceLimits::validate_signature_size(64 * 1024 + 1).is_err());
        assert!(ResourceLimits::validate_decryption_size(100 * 1024 * 1024 + 1).is_err());
    }

    #[test]
    fn test_manager_update_then_validate() {
        let manager = ResourceLimitsManager::new();

        // Initially valid
        assert!(manager.validate_key_derivation_count(500).is_ok());

        // Update to stricter limits
        manager.update_limits(ResourceLimits::new(100, 1024, 512, 2048));

        // Now 500 should fail
        assert!(manager.validate_key_derivation_count(500).is_err());
        assert!(manager.validate_key_derivation_count(100).is_ok());
    }

    #[test]
    fn test_limits_struct_fields_accessible() {
        let limits = ResourceLimits::default();
        // Direct field access
        let _kd = limits.max_key_derivations_per_call;
        let _enc = limits.max_encryption_size_bytes;
        let _sig = limits.max_signature_size_bytes;
        let _dec = limits.max_decryption_size_bytes;
    }

    #[test]
    fn test_error_variants_distinct() {
        let key_err = ResourceError::KeyDerivationLimitExceeded { requested: 100, limit: 50 };
        let enc_err = ResourceError::EncryptionSizeLimitExceeded { requested: 100, limit: 50 };
        let sig_err = ResourceError::SignatureSizeLimitExceeded { requested: 100, limit: 50 };
        let dec_err = ResourceError::DecryptionSizeLimitExceeded { requested: 100, limit: 50 };

        // Each error variant should have distinct display messages
        let key_msg = format!("{}", key_err);
        let enc_msg = format!("{}", enc_err);
        let sig_msg = format!("{}", sig_err);
        let dec_msg = format!("{}", dec_err);

        assert_ne!(key_msg, enc_msg);
        assert_ne!(enc_msg, sig_msg);
        assert_ne!(sig_msg, dec_msg);
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
    fn test_manager_concurrent_reads() {
        let manager = Arc::new(ResourceLimitsManager::new());
        let mut handles = vec![];

        for _ in 0..10 {
            let m = Arc::clone(&manager);
            handles.push(thread::spawn(move || {
                for _ in 0..100 {
                    let limits = m.get_limits();
                    assert_eq!(limits.max_key_derivations_per_call, 1000);
                }
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }
    }

    #[test]
    fn test_manager_concurrent_validations() {
        let manager = Arc::new(ResourceLimitsManager::new());
        let mut handles = vec![];

        for _ in 0..10 {
            let m = Arc::clone(&manager);
            handles.push(thread::spawn(move || {
                for i in 0..100 {
                    let _ = m.validate_key_derivation_count(i);
                    let _ = m.validate_encryption_size(i * 1024);
                    let _ = m.validate_signature_size(i * 10);
                    let _ = m.validate_decryption_size(i * 1024);
                }
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }
    }

    #[test]
    fn test_manager_concurrent_read_write() {
        let manager = Arc::new(ResourceLimitsManager::new());
        let mut handles = vec![];

        // Writers
        for i in 0..5 {
            let m = Arc::clone(&manager);
            handles.push(thread::spawn(move || {
                for j in 0..10 {
                    let limit = (i + 1) * (j + 1) * 100;
                    m.update_limits(ResourceLimits::new(
                        limit,
                        limit * 1000,
                        limit * 10,
                        limit * 1000,
                    ));
                }
            }));
        }

        // Readers
        for _ in 0..5 {
            let m = Arc::clone(&manager);
            handles.push(thread::spawn(move || {
                for _ in 0..50 {
                    let limits = m.get_limits();
                    // Just ensure we can read without panic
                    let _ = limits.max_key_derivations_per_call;
                }
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }
    }

    #[test]
    fn test_global_limits_concurrent_access() {
        let mut handles = vec![];

        for _ in 0..10 {
            handles.push(thread::spawn(|| {
                for _ in 0..100 {
                    let manager = get_global_resource_limits();
                    let limits = manager.get_limits();
                    assert!(limits.max_key_derivations_per_call > 0);
                }
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }
    }
}

// ============================================================================
// Integration Tests
// ============================================================================

mod integration_tests {
    use super::*;

    #[test]
    fn test_typical_encryption_workflow() {
        // Simulate a typical workflow
        let plaintext_size = 1024 * 1024; // 1MB

        // Validate encryption size
        assert!(validate_encryption_size(plaintext_size).is_ok());

        // Validate output (encrypted) size (typically larger due to tag/nonce)
        let ciphertext_size = plaintext_size + 16 + 12; // + tag + nonce
        assert!(validate_encryption_size(ciphertext_size).is_ok());
    }

    #[test]
    fn test_typical_decryption_workflow() {
        let ciphertext_size = 50 * 1024 * 1024; // 50MB

        // Validate decryption size
        assert!(validate_decryption_size(ciphertext_size).is_ok());
    }

    #[test]
    fn test_key_derivation_workflow() {
        // PBKDF2-style iteration count
        let iterations = 100;
        assert!(validate_key_derivation_count(iterations).is_ok());

        // Excessive iterations should fail
        let excessive_iterations = 10_000;
        assert!(validate_key_derivation_count(excessive_iterations).is_err());
    }

    #[test]
    fn test_signature_workflow() {
        // Typical signature sizes
        let ed25519_sig_size = 64;
        let dilithium_sig_size = 2420;
        let sphincs_sig_size = 17088;

        assert!(validate_signature_size(ed25519_sig_size).is_ok());
        assert!(validate_signature_size(dilithium_sig_size).is_ok());
        assert!(validate_signature_size(sphincs_sig_size).is_ok());

        // Unreasonably large signature
        let huge_sig_size = 100 * 1024;
        assert!(validate_signature_size(huge_sig_size).is_err());
    }

    #[test]
    fn test_custom_limits_for_constrained_environment() {
        // Simulate embedded/constrained environment
        let constrained_limits = ResourceLimits::new(
            10,        // Only 10 key derivations
            64 * 1024, // Max 64KB encryption
            256,       // Max 256 byte signatures
            64 * 1024, // Max 64KB decryption
        );
        let manager = ResourceLimitsManager::with_limits(constrained_limits);

        // These should pass for constrained environment
        assert!(manager.validate_key_derivation_count(5).is_ok());
        assert!(manager.validate_encryption_size(32 * 1024).is_ok());
        assert!(manager.validate_signature_size(64).is_ok());
        assert!(manager.validate_decryption_size(32 * 1024).is_ok());

        // These would be fine in normal environment but fail here
        assert!(manager.validate_key_derivation_count(100).is_err());
        assert!(manager.validate_encryption_size(1024 * 1024).is_err());
        assert!(manager.validate_signature_size(1024).is_err());
        assert!(manager.validate_decryption_size(1024 * 1024).is_err());
    }

    #[test]
    fn test_dynamic_limit_adjustment() {
        let manager = ResourceLimitsManager::new();

        // Initial limits
        assert!(manager.validate_encryption_size(50 * 1024 * 1024).is_ok());

        // System detects low memory, tighten limits
        manager.update_limits(ResourceLimits::new(
            100,
            10 * 1024 * 1024,
            32 * 1024,
            10 * 1024 * 1024,
        ));

        // Same operation should now fail
        assert!(manager.validate_encryption_size(50 * 1024 * 1024).is_err());
        assert!(manager.validate_encryption_size(5 * 1024 * 1024).is_ok());

        // Memory freed, relax limits
        manager.update_limits(ResourceLimits::default());

        // Original operation should work again
        assert!(manager.validate_encryption_size(50 * 1024 * 1024).is_ok());
    }
}
