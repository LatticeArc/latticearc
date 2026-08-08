//! FIPS resource-limits and RFC test-vector tests.
//!
//! Covers resource-limit enforcement and RFC-derived cryptographic test
//! vectors for the `latticearc_tests::validation` crate.

#![deny(unsafe_code)]

mod resource_limits {
    //! Comprehensive tests for resource_limits module
    //!
    //! This test suite aims to achieve 80%+ code coverage for resource_limits.rs
    //! by testing all public functions, methods, error paths, and edge cases.

    #![allow(clippy::panic, clippy::unwrap_used, clippy::redundant_clone, clippy::useless_vec)]

    use latticearc_tests::validation::resource_limits::{
        ResourceError, ResourceLimits, ResourceLimitsManager, get_global_resource_limits,
        validate_decryption_size, validate_encryption_size, validate_signature_size,
    };

    // ============================================================================
    // ResourceLimits Struct Tests
    // ============================================================================

    mod resource_limits_struct_tests {
        use super::*;

        #[test]
        fn test_default_creates_expected_values_passes_validation() {
            let limits = ResourceLimits::default();
            assert_eq!(limits.max_encryption_size_bytes, 100 * 1024 * 1024);
            assert_eq!(limits.max_signature_size_bytes, 64 * 1024);
            assert_eq!(limits.max_decryption_size_bytes, 100 * 1024 * 1024);
        }

        #[test]
        fn test_new_with_custom_values_passes_validation() {
            let limits = ResourceLimits::new(50 * 1024 * 1024, 32 * 1024, 25 * 1024 * 1024);
            assert_eq!(limits.max_encryption_size_bytes, 50 * 1024 * 1024);
            assert_eq!(limits.max_signature_size_bytes, 32 * 1024);
            assert_eq!(limits.max_decryption_size_bytes, 25 * 1024 * 1024);
        }

        #[test]
        fn test_new_with_zero_values_passes_validation() {
            let limits = ResourceLimits::new(0, 0, 0);
            assert_eq!(limits.max_encryption_size_bytes, 0);
            assert_eq!(limits.max_signature_size_bytes, 0);
            assert_eq!(limits.max_decryption_size_bytes, 0);
        }

        #[test]
        fn test_new_with_max_values_passes_validation() {
            let limits = ResourceLimits::new(usize::MAX, usize::MAX, usize::MAX);
            assert_eq!(limits.max_encryption_size_bytes, usize::MAX);
            assert_eq!(limits.max_signature_size_bytes, usize::MAX);
            assert_eq!(limits.max_decryption_size_bytes, usize::MAX);
        }

        #[test]
        fn test_clone_trait_succeeds() {
            let original = ResourceLimits::new(200, 300, 400);
            let cloned = original.clone();
            assert_eq!(cloned.max_encryption_size_bytes, 200);
            assert_eq!(cloned.max_signature_size_bytes, 300);
            assert_eq!(cloned.max_decryption_size_bytes, 400);
        }

        #[test]
        fn test_debug_trait_passes_validation() {
            let limits = ResourceLimits::default();
            let debug_str = format!("{:?}", limits);
            assert!(debug_str.contains("ResourceLimits"));
            assert!(debug_str.contains("max_encryption_size_bytes"));
        }
    }

    // ============================================================================
    // ResourceLimits Static Validation Method Tests
    // ============================================================================

    mod resource_limits_static_validation_tests {
        use super::*;

        // Encryption Size Tests
        #[test]
        fn test_validate_encryption_size_zero_passes_validation() {
            assert!(validate_encryption_size(0).is_ok());
        }

        #[test]
        fn test_validate_encryption_size_one_passes_validation() {
            assert!(validate_encryption_size(1).is_ok());
        }

        #[test]
        fn test_validate_encryption_size_at_limit_passes_validation() {
            assert!(validate_encryption_size(100 * 1024 * 1024).is_ok());
        }

        #[test]
        fn test_validate_encryption_size_just_over_limit_enforces_limit_has_correct_size() {
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

        // Signature Size Tests
        #[test]
        fn test_validate_signature_size_zero_passes_validation() {
            assert!(validate_signature_size(0).is_ok());
        }

        #[test]
        fn test_validate_signature_size_one_passes_validation() {
            assert!(validate_signature_size(1).is_ok());
        }

        #[test]
        fn test_validate_signature_size_at_limit_passes_validation() {
            assert!(validate_signature_size(64 * 1024).is_ok());
        }

        #[test]
        fn test_validate_signature_size_just_over_limit_enforces_limit_has_correct_size() {
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

        // Decryption Size Tests
        #[test]
        fn test_validate_decryption_size_zero_passes_validation() {
            assert!(validate_decryption_size(0).is_ok());
        }

        #[test]
        fn test_validate_decryption_size_one_passes_validation() {
            assert!(validate_decryption_size(1).is_ok());
        }

        #[test]
        fn test_validate_decryption_size_at_limit_passes_validation() {
            assert!(validate_decryption_size(100 * 1024 * 1024).is_ok());
        }

        #[test]
        fn test_validate_decryption_size_just_over_limit_enforces_limit_has_correct_size() {
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
    }

    // ============================================================================
    // ResourceLimitsManager Tests
    // ============================================================================

    mod resource_limits_manager_tests {
        use super::*;

        #[test]
        fn test_new_creates_default_limits_passes_validation() {
            let manager = ResourceLimitsManager::new();
            let limits = manager.get_limits().unwrap();
            assert_eq!(limits.max_encryption_size_bytes, 100 * 1024 * 1024);
        }

        #[test]
        fn test_with_limits_custom_values_passes_validation() {
            let custom_limits = ResourceLimits::new(1024, 512, 2048);
            let manager = ResourceLimitsManager::with_limits(custom_limits);
            let limits = manager.get_limits().unwrap();
            assert_eq!(limits.max_encryption_size_bytes, 1024);
            assert_eq!(limits.max_signature_size_bytes, 512);
            assert_eq!(limits.max_decryption_size_bytes, 2048);
        }

        #[test]
        fn test_update_limits_passes_validation() {
            let manager = ResourceLimitsManager::new();
            let new_limits = ResourceLimits::new(512, 256, 1024);
            manager.update_limits(new_limits).unwrap();
            let limits = manager.get_limits().unwrap();
            assert_eq!(limits.max_encryption_size_bytes, 512);
        }

        #[test]
        fn test_default_trait_passes_validation() {
            let manager = ResourceLimitsManager::default();
            let limits = manager.get_limits().unwrap();
            assert_eq!(limits.max_encryption_size_bytes, 100 * 1024 * 1024);
        }

        // Manager Validation Tests - Success Cases
        #[test]
        fn test_manager_validate_encryption_size_valid_passes_validation() {
            let manager = ResourceLimitsManager::new();
            assert!(manager.validate_encryption_size(0).is_ok());
            assert!(manager.validate_encryption_size(50 * 1024 * 1024).is_ok());
            assert!(manager.validate_encryption_size(100 * 1024 * 1024).is_ok());
        }

        #[test]
        fn test_manager_validate_signature_size_valid_passes_validation() {
            let manager = ResourceLimitsManager::new();
            assert!(manager.validate_signature_size(0).is_ok());
            assert!(manager.validate_signature_size(32 * 1024).is_ok());
            assert!(manager.validate_signature_size(64 * 1024).is_ok());
        }

        #[test]
        fn test_manager_validate_decryption_size_valid_passes_validation() {
            let manager = ResourceLimitsManager::new();
            assert!(manager.validate_decryption_size(0).is_ok());
            assert!(manager.validate_decryption_size(50 * 1024 * 1024).is_ok());
            assert!(manager.validate_decryption_size(100 * 1024 * 1024).is_ok());
        }

        // Manager Validation Tests - Error Cases
        #[test]
        fn test_manager_validate_encryption_size_exceeded_enforces_limit_has_correct_size() {
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
        fn test_manager_validate_signature_size_exceeded_enforces_limit_has_correct_size() {
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
        fn test_manager_validate_decryption_size_exceeded_enforces_limit_has_correct_size() {
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
        fn test_manager_with_custom_limits_validation_passes_validation() {
            let custom_limits = ResourceLimits::new(100, 50, 200);
            let manager = ResourceLimitsManager::with_limits(custom_limits);

            // Valid within custom limits
            assert!(manager.validate_encryption_size(100).is_ok());
            assert!(manager.validate_signature_size(50).is_ok());
            assert!(manager.validate_decryption_size(200).is_ok());

            // Exceeded custom limits
            assert!(manager.validate_encryption_size(101).is_err());
            assert!(manager.validate_signature_size(51).is_err());
            assert!(manager.validate_decryption_size(201).is_err());
        }

        #[test]
        fn test_manager_with_zero_limits_enforces_limit_succeeds() {
            let zero_limits = ResourceLimits::new(0, 0, 0);
            let manager = ResourceLimitsManager::with_limits(zero_limits);

            // Only zero should be valid
            assert!(manager.validate_encryption_size(0).is_ok());
            assert!(manager.validate_signature_size(0).is_ok());
            assert!(manager.validate_decryption_size(0).is_ok());

            // Anything above zero should fail
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
        fn test_get_global_resource_limits_returns_manager_passes_validation() {
            let manager = get_global_resource_limits();
            let limits = manager.get_limits().unwrap();
            assert!(limits.max_encryption_size_bytes > 0);
        }

        #[test]
        fn test_get_global_resource_limits_same_instance_passes_validation() {
            let manager1 = get_global_resource_limits();
            let manager2 = get_global_resource_limits();
            // Both should return the same static reference
            let limits1 = manager1.get_limits().unwrap();
            let limits2 = manager2.get_limits().unwrap();
            assert_eq!(limits1.max_encryption_size_bytes, limits2.max_encryption_size_bytes);
        }

        // Global Validation Functions - Success Cases
        #[test]
        fn test_global_validate_encryption_size_valid_passes_validation() {
            assert!(validate_encryption_size(0).is_ok());
            assert!(validate_encryption_size(50 * 1024 * 1024).is_ok());
            assert!(validate_encryption_size(100 * 1024 * 1024).is_ok());
        }

        #[test]
        fn test_global_validate_signature_size_valid_passes_validation() {
            assert!(validate_signature_size(0).is_ok());
            assert!(validate_signature_size(32 * 1024).is_ok());
            assert!(validate_signature_size(64 * 1024).is_ok());
        }

        #[test]
        fn test_global_validate_decryption_size_valid_passes_validation() {
            assert!(validate_decryption_size(0).is_ok());
            assert!(validate_decryption_size(50 * 1024 * 1024).is_ok());
            assert!(validate_decryption_size(100 * 1024 * 1024).is_ok());
        }

        // Global Validation Functions - Error Cases
        #[test]
        fn test_global_validate_encryption_size_exceeded_enforces_limit_has_correct_size() {
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
        fn test_global_validate_signature_size_exceeded_enforces_limit_has_correct_size() {
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
        fn test_global_validate_decryption_size_exceeded_enforces_limit_has_correct_size() {
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
        fn test_global_validate_encryption_size_max_enforces_limit_has_correct_size() {
            let result = validate_encryption_size(usize::MAX);
            assert!(result.is_err());
        }

        #[test]
        fn test_global_validate_signature_size_max_enforces_limit_has_correct_size() {
            let result = validate_signature_size(usize::MAX);
            assert!(result.is_err());
        }

        #[test]
        fn test_global_validate_decryption_size_max_enforces_limit_has_correct_size() {
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
        fn test_key_derivation_error_display_passes_validation() {
            let err = ResourceError::KeyDerivationLimitExceeded { requested: 2000, limit: 1000 };
            let msg = format!("{err}");
            assert!(msg.contains("Key derivation"));
            assert!(msg.contains("2000"));
            assert!(msg.contains("1000"));
        }

        #[test]
        fn test_encryption_size_error_display_passes_validation() {
            let err = ResourceError::EncryptionSizeLimitExceeded {
                requested: 200 * 1024 * 1024,
                limit: 100 * 1024 * 1024,
            };
            let msg = format!("{err}");
            assert!(msg.contains("Encryption size"));
        }

        #[test]
        fn test_signature_size_error_display_passes_validation() {
            let err = ResourceError::SignatureSizeLimitExceeded {
                requested: 100 * 1024,
                limit: 64 * 1024,
            };
            let msg = format!("{err}");
            assert!(msg.contains("Signature size"));
        }

        #[test]
        fn test_decryption_size_error_display_passes_validation() {
            let err = ResourceError::DecryptionSizeLimitExceeded {
                requested: 200 * 1024 * 1024,
                limit: 100 * 1024 * 1024,
            };
            let msg = format!("{err}");
            assert!(msg.contains("Decryption size"));
        }

        #[test]
        fn test_key_derivation_error_debug_passes_validation() {
            let err = ResourceError::KeyDerivationLimitExceeded { requested: 2000, limit: 1000 };
            let debug = format!("{:?}", err);
            assert!(debug.contains("KeyDerivationLimitExceeded"));
            assert!(debug.contains("2000"));
            assert!(debug.contains("1000"));
        }

        #[test]
        fn test_encryption_size_error_debug_passes_validation() {
            let err = ResourceError::EncryptionSizeLimitExceeded { requested: 200, limit: 100 };
            let debug = format!("{:?}", err);
            assert!(debug.contains("EncryptionSizeLimitExceeded"));
        }

        #[test]
        fn test_signature_size_error_debug_passes_validation() {
            let err = ResourceError::SignatureSizeLimitExceeded { requested: 100, limit: 50 };
            let debug = format!("{:?}", err);
            assert!(debug.contains("SignatureSizeLimitExceeded"));
        }

        #[test]
        fn test_decryption_size_error_debug_passes_validation() {
            let err = ResourceError::DecryptionSizeLimitExceeded { requested: 200, limit: 100 };
            let debug = format!("{:?}", err);
            assert!(debug.contains("DecryptionSizeLimitExceeded"));
        }

        #[test]
        fn test_error_is_std_error_passes_validation() {
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
        fn test_all_validations_at_exact_limits_passes_validation() {
            // Test that exact limit values are accepted
            assert!(validate_encryption_size(100 * 1024 * 1024).is_ok());
            assert!(validate_signature_size(64 * 1024).is_ok());
            assert!(validate_decryption_size(100 * 1024 * 1024).is_ok());
        }

        #[test]
        fn test_all_validations_one_over_limits_enforces_limit_succeeds() {
            // Test that limit + 1 is rejected
            assert!(validate_encryption_size(100 * 1024 * 1024 + 1).is_err());
            assert!(validate_signature_size(64 * 1024 + 1).is_err());
            assert!(validate_decryption_size(100 * 1024 * 1024 + 1).is_err());
        }

        #[test]
        fn test_limits_struct_fields_accessible_passes_validation() {
            let limits = ResourceLimits::default();
            // Direct field access
            let _enc = limits.max_encryption_size_bytes;
            let _sig = limits.max_signature_size_bytes;
            let _dec = limits.max_decryption_size_bytes;
        }

        #[test]
        fn test_error_variants_distinct_passes_validation() {
            let key_err = ResourceError::KeyDerivationLimitExceeded { requested: 100, limit: 50 };
            let enc_err = ResourceError::EncryptionSizeLimitExceeded { requested: 100, limit: 50 };
            let sig_err = ResourceError::SignatureSizeLimitExceeded { requested: 100, limit: 50 };
            let dec_err = ResourceError::DecryptionSizeLimitExceeded { requested: 100, limit: 50 };

            // Each error variant should have distinct display messages
            let key_msg = format!("{key_err}");
            let enc_msg = format!("{enc_err}");
            let sig_msg = format!("{sig_err}");
            let dec_msg = format!("{dec_err}");

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
        fn test_manager_concurrent_reads_succeeds() {
            let manager = Arc::new(ResourceLimitsManager::new());
            let mut handles = vec![];

            for _ in 0..10 {
                let m = Arc::clone(&manager);
                handles.push(thread::spawn(move || {
                    for _ in 0..100 {
                        let limits = m.get_limits().unwrap();
                        assert_eq!(limits.max_encryption_size_bytes, 100 * 1024 * 1024);
                    }
                }));
            }

            for handle in handles {
                handle.join().unwrap();
            }
        }

        #[test]
        fn test_manager_concurrent_validations_succeeds() {
            let manager = Arc::new(ResourceLimitsManager::new());
            let mut handles = vec![];

            for _ in 0..10 {
                let m = Arc::clone(&manager);
                handles.push(thread::spawn(move || {
                    for i in 0..100 {
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
        fn test_manager_concurrent_read_write_succeeds() {
            let manager = Arc::new(ResourceLimitsManager::new());
            let mut handles = vec![];

            // Writers
            for i in 0..5 {
                let m = Arc::clone(&manager);
                handles.push(thread::spawn(move || {
                    for j in 0..10 {
                        let limit = (i + 1) * (j + 1) * 100;
                        m.update_limits(ResourceLimits::new(
                            limit * 1000,
                            limit * 10,
                            limit * 1000,
                        ))
                        .unwrap();
                    }
                }));
            }

            // Readers
            for _ in 0..5 {
                let m = Arc::clone(&manager);
                handles.push(thread::spawn(move || {
                    for _ in 0..50 {
                        let limits = m.get_limits().unwrap();
                        // Just ensure we can read without panic
                        let _ = limits.max_encryption_size_bytes;
                    }
                }));
            }

            for handle in handles {
                handle.join().unwrap();
            }
        }

        #[test]
        fn test_global_limits_concurrent_access_succeeds() {
            let mut handles = vec![];

            for _ in 0..10 {
                handles.push(thread::spawn(|| {
                    for _ in 0..100 {
                        let manager = get_global_resource_limits();
                        let limits = manager.get_limits().unwrap();
                        assert!(limits.max_encryption_size_bytes > 0);
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
        fn test_typical_encryption_workflow_passes_validation() {
            // Simulate a typical workflow
            let plaintext_size = 1024 * 1024; // 1MB

            // Validate encryption size
            assert!(validate_encryption_size(plaintext_size).is_ok());

            // Validate output (encrypted) size (typically larger due to tag/nonce)
            let ciphertext_size = plaintext_size + 16 + 12; // + tag + nonce
            assert!(validate_encryption_size(ciphertext_size).is_ok());
        }

        #[test]
        fn test_typical_decryption_workflow_passes_validation() {
            let ciphertext_size = 50 * 1024 * 1024; // 50MB

            // Validate decryption size
            assert!(validate_decryption_size(ciphertext_size).is_ok());
        }

        #[test]
        fn test_signature_workflow_passes_validation() {
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
        fn test_custom_limits_for_constrained_environment_passes_validation() {
            // Simulate embedded/constrained environment
            let constrained_limits = ResourceLimits::new(
                64 * 1024, // Max 64KB encryption
                256,       // Max 256 byte signatures
                64 * 1024, // Max 64KB decryption
            );
            let manager = ResourceLimitsManager::with_limits(constrained_limits);

            // These should pass for constrained environment
            assert!(manager.validate_encryption_size(32 * 1024).is_ok());
            assert!(manager.validate_signature_size(64).is_ok());
            assert!(manager.validate_decryption_size(32 * 1024).is_ok());

            // These would be fine in normal environment but fail here
            assert!(manager.validate_encryption_size(1024 * 1024).is_err());
            assert!(manager.validate_signature_size(1024).is_err());
            assert!(manager.validate_decryption_size(1024 * 1024).is_err());
        }

        #[test]
        fn test_dynamic_limit_adjustment_passes_validation() {
            let manager = ResourceLimitsManager::new();

            // Initial limits
            assert!(manager.validate_encryption_size(50 * 1024 * 1024).is_ok());

            // System detects low memory, tighten limits
            manager
                .update_limits(ResourceLimits::new(10 * 1024 * 1024, 32 * 1024, 10 * 1024 * 1024))
                .unwrap();

            // Same operation should now fail
            assert!(manager.validate_encryption_size(50 * 1024 * 1024).is_err());
            assert!(manager.validate_encryption_size(5 * 1024 * 1024).is_ok());

            // Memory freed, relax limits
            manager.update_limits(ResourceLimits::default()).unwrap();

            // Original operation should work again
            assert!(manager.validate_encryption_size(50 * 1024 * 1024).is_ok());
        }
    }
}

mod rfc_vectors {
    //! Comprehensive tests for RFC test vectors module
    //!
    //! This module tests the public APIs of latticearc_tests::validation::rfc_vectors including:
    //! - RfcTestError error types and formatting
    //! - RfcTestResults tracking and reporting
    //! - Additional RFC test vector validation scenarios
    //! - Edge cases and error handling paths

    #![allow(
        clippy::panic,
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::cast_precision_loss,
        clippy::useless_vec
    )]

    use latticearc_tests::validation::rfc_vectors::{RfcTestError, RfcTestResults};

    // =============================================================================
    // RfcTestResults Tests
    // =============================================================================

    #[test]
    fn test_rfc_test_results_new_is_empty() {
        let results = RfcTestResults::new();
        assert_eq!(results.total, 0);
        assert_eq!(results.passed, 0);
        assert_eq!(results.failed, 0);
        assert!(results.failures.is_empty());
    }

    #[test]
    fn test_rfc_test_results_default_is_empty() {
        let results = RfcTestResults::default();
        assert_eq!(results.total, 0);
        assert_eq!(results.passed, 0);
        assert_eq!(results.failed, 0);
        assert!(results.failures.is_empty());
    }

    #[test]
    fn test_rfc_test_results_add_pass_increments_counts_succeeds() {
        let mut results = RfcTestResults::new();
        results.add_pass();

        assert_eq!(results.total, 1);
        assert_eq!(results.passed, 1);
        assert_eq!(results.failed, 0);
        assert!(results.failures.is_empty());
    }

    #[test]
    fn test_rfc_test_results_add_multiple_passes_increments_counts_succeeds() {
        let mut results = RfcTestResults::new();

        for _ in 0..10 {
            results.add_pass();
        }

        assert_eq!(results.total, 10);
        assert_eq!(results.passed, 10);
        assert_eq!(results.failed, 0);
        assert!(results.failures.is_empty());
    }

    #[test]
    fn test_rfc_test_results_add_failure_increments_counts_fails() {
        let mut results = RfcTestResults::new();
        results.add_failure("Test failure message".to_string());

        assert_eq!(results.total, 1);
        assert_eq!(results.passed, 0);
        assert_eq!(results.failed, 1);
        assert_eq!(results.failures.len(), 1);
        assert_eq!(results.failures[0], "Test failure message");
    }

    #[test]
    fn test_rfc_test_results_add_multiple_failures_increments_counts_fails() {
        let mut results = RfcTestResults::new();

        results.add_failure("Failure 1".to_string());
        results.add_failure("Failure 2".to_string());
        results.add_failure("Failure 3".to_string());

        assert_eq!(results.total, 3);
        assert_eq!(results.passed, 0);
        assert_eq!(results.failed, 3);
        assert_eq!(results.failures.len(), 3);
        assert_eq!(results.failures[0], "Failure 1");
        assert_eq!(results.failures[1], "Failure 2");
        assert_eq!(results.failures[2], "Failure 3");
    }

    #[test]
    fn test_rfc_test_results_mixed_pass_and_fail_tracks_correctly_fails() {
        let mut results = RfcTestResults::new();

        results.add_pass();
        results.add_pass();
        results.add_failure("Failure A".to_string());
        results.add_pass();
        results.add_failure("Failure B".to_string());

        assert_eq!(results.total, 5);
        assert_eq!(results.passed, 3);
        assert_eq!(results.failed, 2);
        assert_eq!(results.failures.len(), 2);
    }

    #[test]
    fn test_rfc_test_results_all_passed_returns_true_succeeds() {
        let mut results = RfcTestResults::new();
        results.add_pass();
        results.add_pass();
        results.add_pass();

        assert!(results.all_passed());
    }

    #[test]
    fn test_rfc_test_results_all_passed_returns_false_with_failures_fails() {
        let mut results = RfcTestResults::new();
        results.add_pass();
        results.add_failure("failure".to_string());
        results.add_pass();

        assert!(!results.all_passed());
    }

    #[test]
    fn test_rfc_test_results_all_passed_returns_true_when_empty_succeeds() {
        let results = RfcTestResults::new();
        // Empty results technically have no failures
        assert!(results.all_passed());
    }

    #[test]
    fn test_rfc_test_results_debug_has_correct_format() {
        let mut results = RfcTestResults::new();
        results.add_pass();
        results.add_failure("test failure".to_string());

        let debug_str = format!("{:?}", results);
        assert!(debug_str.contains("RfcTestResults"));
        assert!(debug_str.contains("total"));
        assert!(debug_str.contains("passed"));
        assert!(debug_str.contains("failed"));
        assert!(debug_str.contains("failures"));
    }

    #[test]
    fn test_rfc_test_results_failure_messages_are_preserved_fails() {
        let mut results = RfcTestResults::new();

        let messages = vec![
            "RFC 8439: encryption failed".to_string(),
            "RFC 8032: signature mismatch".to_string(),
            "RFC 7748: key derivation error".to_string(),
            "RFC 5869: HKDF expansion failed".to_string(),
        ];

        for msg in &messages {
            results.add_failure(msg.clone());
        }

        assert_eq!(results.failures, messages);
    }

    #[test]
    fn test_rfc_test_results_empty_failure_message_is_preserved_fails() {
        let mut results = RfcTestResults::new();
        results.add_failure(String::new());

        assert_eq!(results.failed, 1);
        assert_eq!(results.failures[0], "");
    }

    #[test]
    fn test_rfc_test_results_unicode_failure_message_is_preserved_fails() {
        let mut results = RfcTestResults::new();
        results.add_failure("Test failed: \u{2718} validation error \u{1F512}".to_string());

        assert_eq!(results.failed, 1);
        assert!(results.failures[0].contains("\u{2718}"));
    }

    #[test]
    fn test_rfc_test_results_large_number_of_tests_tracks_correctly_succeeds() {
        let mut results = RfcTestResults::new();

        for i in 0..1000 {
            if i % 10 == 0 {
                results.add_failure(format!("Failure at test {}", i));
            } else {
                results.add_pass();
            }
        }

        assert_eq!(results.total, 1000);
        assert_eq!(results.passed, 900);
        assert_eq!(results.failed, 100);
        assert_eq!(results.failures.len(), 100);
    }

    // =============================================================================
    // RfcTestError Tests
    // =============================================================================

    #[test]
    fn test_rfc_test_error_test_failed_display_has_correct_format() {
        let error = RfcTestError::TestFailed {
            rfc: "RFC 8439".to_string(),
            test_name: "ChaCha20-Poly1305 AEAD".to_string(),
            message: "ciphertext mismatch".to_string(),
        };

        let display = format!("{error}");
        assert!(display.contains("RFC 8439"));
        assert!(display.contains("ChaCha20-Poly1305 AEAD"));
        assert!(display.contains("ciphertext mismatch"));
    }

    #[test]
    fn test_rfc_test_error_hex_error_display_has_correct_format() {
        let error = RfcTestError::HexError("invalid hex character 'g'".to_string());

        let display = format!("{error}");
        assert!(display.contains("Hex decode error"));
        assert!(display.contains("invalid hex character 'g'"));
    }

    #[test]
    fn test_rfc_test_error_debug_has_correct_format() {
        let error = RfcTestError::TestFailed {
            rfc: "RFC 8032".to_string(),
            test_name: "Ed25519".to_string(),
            message: "signature verification failed".to_string(),
        };

        let debug = format!("{:?}", error);
        assert!(debug.contains("TestFailed"));
        assert!(debug.contains("RFC 8032"));
        assert!(debug.contains("Ed25519"));
        assert!(debug.contains("signature verification failed"));
    }

    #[test]
    fn test_rfc_test_error_hex_error_debug_has_correct_format() {
        let error = RfcTestError::HexError("odd length".to_string());

        let debug = format!("{:?}", error);
        assert!(debug.contains("HexError"));
        assert!(debug.contains("odd length"));
    }

    #[test]
    fn test_rfc_test_error_test_failed_empty_fields_displays_correctly_fails() {
        let error = RfcTestError::TestFailed {
            rfc: String::new(),
            test_name: String::new(),
            message: String::new(),
        };

        let display = format!("{error}");
        assert!(display.contains("RFC test failed"));
    }

    #[test]
    fn test_rfc_test_error_test_failed_special_characters_displays_correctly_fails() {
        let error = RfcTestError::TestFailed {
            rfc: "RFC-8439 (ChaCha20)".to_string(),
            test_name: "Test <vector> #1".to_string(),
            message: "Expected 0x00 but got 0xff".to_string(),
        };

        let display = format!("{error}");
        assert!(display.contains("RFC-8439 (ChaCha20)"));
        assert!(display.contains("Test <vector> #1"));
        assert!(display.contains("Expected 0x00 but got 0xff"));
    }

    #[test]
    fn test_rfc_test_error_hex_error_empty_displays_correctly_fails() {
        let error = RfcTestError::HexError(String::new());

        let display = format!("{error}");
        assert!(display.contains("Hex decode error"));
    }

    #[test]
    fn test_rfc_test_error_implements_std_error_succeeds() {
        let error: Box<dyn std::error::Error> = Box::new(RfcTestError::TestFailed {
            rfc: "RFC 7748".to_string(),
            test_name: "X25519".to_string(),
            message: "shared secret mismatch".to_string(),
        });

        // Verify we can use it as a std::error::Error
        let _description = error.to_string();
        assert!(error.source().is_none()); // RfcTestError has no source error
    }

    #[test]
    fn test_rfc_test_error_hex_implements_std_error_succeeds() {
        let error: Box<dyn std::error::Error> =
            Box::new(RfcTestError::HexError("invalid character at position 5".to_string()));

        let _description = error.to_string();
        assert!(error.source().is_none());
    }

    // =============================================================================
    // Integration-style tests using RfcTestResults
    // =============================================================================

    #[test]
    fn test_rfc_test_results_typical_workflow_succeeds() {
        let mut results = RfcTestResults::new();

        // Simulate running a test suite
        // Test 1: passes
        let test1_result: Result<(), &str> = Ok(());
        if test1_result.is_ok() {
            results.add_pass();
        } else {
            results.add_failure("Test 1 failed".to_string());
        }

        // Test 2: passes
        let test2_result: Result<(), &str> = Ok(());
        if test2_result.is_ok() {
            results.add_pass();
        } else {
            results.add_failure("Test 2 failed".to_string());
        }

        // Test 3: fails
        let test3_result: Result<(), &str> = Err("validation error");
        if test3_result.is_ok() {
            results.add_pass();
        } else {
            results.add_failure(format!("Test 3 failed: {:?}", test3_result.err()));
        }

        assert_eq!(results.total, 3);
        assert_eq!(results.passed, 2);
        assert_eq!(results.failed, 1);
        assert!(!results.all_passed());
    }

    #[test]
    fn test_rfc_test_results_report_generation_succeeds() {
        let mut results = RfcTestResults::new();

        // Add some test results
        results.add_pass();
        results.add_pass();
        results.add_failure("ChaCha20: tag mismatch".to_string());
        results.add_pass();
        results.add_failure("HKDF: expansion too long".to_string());

        // Generate a summary report
        let pass_rate = if results.total > 0 {
            (results.passed as f64 / results.total as f64) * 100.0
        } else {
            0.0
        };

        assert_eq!(results.total, 5);
        assert!((pass_rate - 60.0).abs() < 0.001);
        assert_eq!(results.failures.len(), 2);
    }

    // =============================================================================
    // Additional RFC Vector Validation Tests
    // =============================================================================

    /// Test hex decoding scenarios that could trigger HexError
    #[test]
    fn test_hex_decoding_valid_succeeds() {
        let valid_hex = "0123456789abcdef";
        let result = hex::decode(valid_hex);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]);
    }

    #[test]
    fn test_hex_decoding_uppercase_matches_expected() {
        let valid_hex = "0123456789ABCDEF";
        let result = hex::decode(valid_hex);
        assert!(result.is_ok());
    }

    #[test]
    fn test_hex_decoding_mixed_case_succeeds() {
        let valid_hex = "0123456789AbCdEf";
        let result = hex::decode(valid_hex);
        assert!(result.is_ok());
    }

    #[test]
    fn test_hex_decoding_empty_succeeds() {
        let empty_hex = "";
        let result = hex::decode(empty_hex);
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn test_hex_decoding_invalid_char_returns_error() {
        let invalid_hex = "0123456789abcdeg";
        let result = hex::decode(invalid_hex);
        assert!(result.is_err());
    }

    #[test]
    fn test_hex_decoding_odd_length_returns_error() {
        let odd_hex = "0123456789abcde";
        let result = hex::decode(odd_hex);
        assert!(result.is_err());
    }

    #[test]
    fn test_hex_decoding_whitespace_fails() {
        let hex_with_space = "01 23 45";
        let result = hex::decode(hex_with_space);
        assert!(result.is_err());
    }

    // =============================================================================
    // Edge Cases for Test Results
    // =============================================================================

    #[test]
    fn test_rfc_test_results_consistency_matches_expected() {
        let mut results = RfcTestResults::new();

        // Track independently
        let mut expected_total = 0usize;
        let mut expected_passed = 0usize;
        let mut expected_failed = 0usize;

        for i in 0..50 {
            if i % 3 == 0 {
                results.add_failure(format!("fail {}", i));
                expected_total += 1;
                expected_failed += 1;
            } else {
                results.add_pass();
                expected_total += 1;
                expected_passed += 1;
            }
        }

        // Verify consistency: total == passed + failed
        assert_eq!(results.total, results.passed + results.failed);
        assert_eq!(results.total, expected_total);
        assert_eq!(results.passed, expected_passed);
        assert_eq!(results.failed, expected_failed);
    }

    #[test]
    fn test_rfc_test_results_failure_order_preserved_fails() {
        let mut results = RfcTestResults::new();

        let failures = vec!["first", "second", "third", "fourth", "fifth"];
        for (i, f) in failures.iter().enumerate() {
            if i % 2 == 0 {
                results.add_pass();
            }
            results.add_failure(f.to_string());
        }

        // Verify failures are in insertion order
        for (i, f) in failures.iter().enumerate() {
            assert_eq!(results.failures[i], *f);
        }
    }

    #[test]
    fn test_rfc_test_results_long_failure_message_matches_expected() {
        let mut results = RfcTestResults::new();

        let long_message = "A".repeat(10000);
        results.add_failure(long_message.clone());

        assert_eq!(results.failures[0], long_message);
        assert_eq!(results.failures[0].len(), 10000);
    }

    // =============================================================================
    // Error Variant Coverage Tests
    // =============================================================================

    #[test]
    fn test_all_rfc_error_variants_succeed_fails() {
        // Test TestFailed variant
        let test_failed = RfcTestError::TestFailed {
            rfc: "RFC 5869".to_string(),
            test_name: "HKDF-SHA256 Test 1".to_string(),
            message: "PRK mismatch".to_string(),
        };

        // Test HexError variant
        let hex_error = RfcTestError::HexError("invalid input".to_string());

        // Both should implement Display
        let _ = format!("{test_failed}");
        let _ = format!("{hex_error}");

        // Both should implement Debug
        let _ = format!("{:?}", test_failed);
        let _ = format!("{:?}", hex_error);
    }

    #[test]
    fn test_rfc_test_error_field_access_succeeds() {
        // Create error and verify fields via pattern matching
        let error = RfcTestError::TestFailed {
            rfc: "RFC 8032".to_string(),
            test_name: "Test Vector 1".to_string(),
            message: "Signature mismatch at byte 32".to_string(),
        };

        match error {
            RfcTestError::TestFailed { rfc, test_name, message } => {
                assert_eq!(rfc, "RFC 8032");
                assert_eq!(test_name, "Test Vector 1");
                assert_eq!(message, "Signature mismatch at byte 32");
            }
            _ => panic!("Expected TestFailed variant"),
        }
    }

    #[test]
    fn test_rfc_test_error_hex_error_field_access_succeeds() {
        let error = RfcTestError::HexError("position 42: invalid digit".to_string());

        match error {
            RfcTestError::HexError(msg) => {
                assert!(msg.contains("position 42"));
                assert!(msg.contains("invalid digit"));
            }
            _ => panic!("Expected HexError variant"),
        }
    }

    // =============================================================================
    // Simulated RFC Test Workflow Tests
    // =============================================================================

    #[test]
    fn test_simulated_chacha20_poly1305_workflow_succeeds() {
        use chacha20poly1305::{
            ChaCha20Poly1305,
            aead::{Aead, KeyInit, Payload},
        };

        let mut results = RfcTestResults::new();

        // Generate a test key and nonce
        let key = [0x42u8; 32];
        let nonce = [0u8; 12];
        let plaintext = b"test message for RFC 8439";
        let aad = b"additional data";

        let cipher = ChaCha20Poly1305::new(&key.into());

        // Test encryption
        match cipher.encrypt((&nonce).into(), Payload { msg: plaintext, aad }) {
            Ok(ciphertext) => {
                results.add_pass();

                // Test decryption
                match cipher.decrypt((&nonce).into(), Payload { msg: &ciphertext, aad }) {
                    Ok(decrypted) => {
                        if decrypted == plaintext {
                            results.add_pass();
                        } else {
                            results
                                .add_failure("Decrypted text doesn't match original".to_string());
                        }
                    }
                    Err(e) => {
                        results.add_failure(format!("Decryption failed: {:?}", e));
                    }
                }
            }
            Err(e) => {
                results.add_failure(format!("Encryption failed: {:?}", e));
            }
        }

        assert!(results.all_passed(), "Failures: {:?}", results.failures);
    }

    #[test]
    fn test_simulated_x25519_workflow_succeeds() {
        use x25519_dalek::{PublicKey, StaticSecret};

        let mut results = RfcTestResults::new();

        // Alice generates key pair
        let alice_secret = StaticSecret::from([1u8; 32]);
        let alice_public = PublicKey::from(&alice_secret);

        // Bob generates key pair
        let bob_secret = StaticSecret::from([2u8; 32]);
        let bob_public = PublicKey::from(&bob_secret);

        // Both compute shared secret
        let shared_alice = alice_secret.diffie_hellman(&bob_public);
        let shared_bob = bob_secret.diffie_hellman(&alice_public);

        if shared_alice.as_bytes() == shared_bob.as_bytes() {
            results.add_pass();
        } else {
            results.add_failure("X25519 shared secrets don't match".to_string());
        }

        // Verify public key derivation is deterministic
        let alice_secret_2 = StaticSecret::from([1u8; 32]);
        let alice_public_2 = PublicKey::from(&alice_secret_2);

        if alice_public.as_bytes() == alice_public_2.as_bytes() {
            results.add_pass();
        } else {
            results.add_failure("X25519 key derivation not deterministic".to_string());
        }

        assert!(results.all_passed(), "Failures: {:?}", results.failures);
    }

    #[test]
    fn test_simulated_ed25519_workflow_succeeds() {
        use ed25519_dalek::{Signer, SigningKey, Verifier};

        let mut results = RfcTestResults::new();

        // Generate key pair from fixed seed
        let secret_key = [42u8; 32];
        let signing_key = SigningKey::from_bytes(&secret_key);
        let verifying_key = signing_key.verifying_key();

        // Sign a message
        let message = b"Test message for Ed25519";
        let signature = signing_key.sign(message);

        // Verify signature
        if verifying_key.verify(message, &signature).is_ok() {
            results.add_pass();
        } else {
            results.add_failure("Ed25519 signature verification failed".to_string());
        }

        // Verify signature fails for wrong message
        let wrong_message = b"Wrong message";
        if verifying_key.verify(wrong_message, &signature).is_err() {
            results.add_pass();
        } else {
            results.add_failure("Ed25519 verification should fail for wrong message".to_string());
        }

        assert!(results.all_passed(), "Failures: {:?}", results.failures);
    }

    #[test]
    fn test_simulated_hkdf_workflow_succeeds() {
        use hkdf::Hkdf;
        use sha2::Sha256;

        let mut results = RfcTestResults::new();

        let ikm = b"input keying material";
        let salt = b"optional salt";
        let info = b"context info";

        let hk = Hkdf::<Sha256>::new(Some(salt), ikm);

        // Test expansion to various lengths
        let lengths = [16, 32, 64, 128];

        for &len in &lengths {
            let mut okm = vec![0u8; len];
            if hk.expand(info, &mut okm).is_ok() {
                results.add_pass();
            } else {
                results.add_failure(format!("HKDF expansion to {} bytes failed", len));
            }
        }

        // Test determinism
        let mut okm1 = vec![0u8; 32];
        let mut okm2 = vec![0u8; 32];

        let hk1 = Hkdf::<Sha256>::new(Some(salt), ikm);
        let hk2 = Hkdf::<Sha256>::new(Some(salt), ikm);

        let _ = hk1.expand(info, &mut okm1);
        let _ = hk2.expand(info, &mut okm2);

        if okm1 == okm2 {
            results.add_pass();
        } else {
            results.add_failure("HKDF not deterministic".to_string());
        }

        assert!(results.all_passed(), "Failures: {:?}", results.failures);
    }

    #[test]
    fn test_simulated_sha256_workflow_succeeds() {
        use sha2::{Digest, Sha256};

        let mut results = RfcTestResults::new();

        // Test empty input
        let mut hasher = Sha256::new();
        hasher.update(b"");
        let result = hasher.finalize();

        // Known SHA-256 of empty string
        let expected =
            hex::decode("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
                .unwrap();

        if result.as_slice() == expected.as_slice() {
            results.add_pass();
        } else {
            results.add_failure("SHA-256 of empty string mismatch".to_string());
        }

        // Test "abc"
        let mut hasher = Sha256::new();
        hasher.update(b"abc");
        let result = hasher.finalize();

        let expected =
            hex::decode("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
                .unwrap();

        if result.as_slice() == expected.as_slice() {
            results.add_pass();
        } else {
            results.add_failure("SHA-256 of 'abc' mismatch".to_string());
        }

        // Test incremental hashing
        let mut hasher1 = Sha256::new();
        hasher1.update(b"hello ");
        hasher1.update(b"world");
        let result1 = hasher1.finalize();

        let mut hasher2 = Sha256::new();
        hasher2.update(b"hello world");
        let result2 = hasher2.finalize();

        if result1 == result2 {
            results.add_pass();
        } else {
            results.add_failure("SHA-256 incremental hashing mismatch".to_string());
        }

        assert!(results.all_passed(), "Failures: {:?}", results.failures);
    }

    // =============================================================================
    // AES-GCM Tests
    // =============================================================================

    #[test]
    fn test_simulated_aes_gcm_workflow_succeeds() {
        use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};

        let mut results = RfcTestResults::new();

        let key = [0x42u8; 32];
        let nonce_bytes = [0u8; 12];
        let plaintext = b"test plaintext for AES-GCM";
        let aad = b"additional authenticated data";

        let unbound_key = UnboundKey::new(&AES_256_GCM, &key).expect("key creation");
        let sealing_key = LessSafeKey::new(unbound_key);

        let nonce = Nonce::assume_unique_for_key(nonce_bytes);

        let mut in_out = plaintext.to_vec();
        if sealing_key.seal_in_place_append_tag(nonce, Aad::from(aad), &mut in_out).is_ok() {
            results.add_pass();

            // Test decryption
            let unbound_key2 = UnboundKey::new(&AES_256_GCM, &key).expect("key creation");
            let opening_key = LessSafeKey::new(unbound_key2);
            let nonce2 = Nonce::assume_unique_for_key(nonce_bytes);

            if let Ok(decrypted) = opening_key.open_in_place(nonce2, Aad::from(aad), &mut in_out) {
                if decrypted == plaintext {
                    results.add_pass();
                } else {
                    results.add_failure("AES-GCM decryption mismatch".to_string());
                }
            } else {
                results.add_failure("AES-GCM decryption failed".to_string());
            }
        } else {
            results.add_failure("AES-GCM encryption failed".to_string());
        }

        assert!(results.all_passed(), "Failures: {:?}", results.failures);
    }

    // =============================================================================
    // Boundary and Stress Tests
    // =============================================================================

    #[test]
    fn test_rfc_test_results_stress_tracks_correctly_succeeds() {
        let mut results = RfcTestResults::new();

        // Simulate a large test suite
        for i in 0..10000 {
            if i % 100 == 99 {
                results.add_failure(format!("Test {} failed", i));
            } else {
                results.add_pass();
            }
        }

        assert_eq!(results.total, 10000);
        assert_eq!(results.passed, 9900);
        assert_eq!(results.failed, 100);
        assert_eq!(results.failures.len(), 100);
        assert!(!results.all_passed());
    }

    #[test]
    fn test_rfc_test_results_many_failures_tracks_correctly_fails() {
        let mut results = RfcTestResults::new();

        // All failures
        for i in 0..1000 {
            results.add_failure(format!("All tests fail: {}", i));
        }

        assert_eq!(results.total, 1000);
        assert_eq!(results.passed, 0);
        assert_eq!(results.failed, 1000);
        assert!(!results.all_passed());
    }

    #[test]
    fn test_rfc_test_results_all_passes_tracks_correctly_succeeds() {
        let mut results = RfcTestResults::new();

        // All passes
        for _ in 0..1000 {
            results.add_pass();
        }

        assert_eq!(results.total, 1000);
        assert_eq!(results.passed, 1000);
        assert_eq!(results.failed, 0);
        assert!(results.all_passed());
    }
}
