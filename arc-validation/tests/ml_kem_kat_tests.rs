//! Comprehensive tests for arc-validation/src/nist_kat/ml_kem_kat.rs
//!
//! This test module provides comprehensive coverage of the ML-KEM Known Answer Test
//! implementation, including:
//! - All public functions (run_ml_kem_512_kat, run_ml_kem_768_kat, run_ml_kem_1024_kat)
//! - Test vector struct field access and validation
//! - Error handling paths
//! - Edge cases and boundary conditions
//! - Individual test vector execution
//!
//! Target: Improve coverage from 74.47% to 80%+

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

use arc_validation::nist_kat::{KatRunner, NistKatError, decode_hex, ml_kem_kat};

// ============================================================================
// MlKemTestVector Struct Tests
// ============================================================================

mod ml_kem_test_vector_tests {
    use super::*;

    #[test]
    fn test_ml_kem_512_vector_1_field_access() {
        // Access all fields of the first ML-KEM-512 test vector
        let vector = &ml_kem_kat::ML_KEM_512_VECTORS[0];

        assert_eq!(vector.test_name, "ML-KEM-512-KAT-1");
        assert!(!vector.seed.is_empty());
        assert!(!vector.expected_pk.is_empty());
        assert!(!vector.expected_sk.is_empty());
        assert!(!vector.expected_ct.is_empty());
        assert!(!vector.expected_ss.is_empty());
    }

    #[test]
    fn test_ml_kem_512_vector_2_field_access() {
        // Access all fields of the second ML-KEM-512 test vector
        let vector = &ml_kem_kat::ML_KEM_512_VECTORS[1];

        assert_eq!(vector.test_name, "ML-KEM-512-KAT-2");
        assert!(!vector.seed.is_empty());
        assert!(!vector.expected_pk.is_empty());
        assert!(!vector.expected_sk.is_empty());
        assert!(!vector.expected_ct.is_empty());
        assert!(!vector.expected_ss.is_empty());
    }

    #[test]
    fn test_ml_kem_768_vector_1_field_access() {
        // Access all fields of the first ML-KEM-768 test vector
        let vector = &ml_kem_kat::ML_KEM_768_VECTORS[0];

        assert_eq!(vector.test_name, "ML-KEM-768-KAT-1");
        assert!(!vector.seed.is_empty());
        assert!(!vector.expected_pk.is_empty());
        assert!(!vector.expected_sk.is_empty());
        assert!(!vector.expected_ct.is_empty());
        assert!(!vector.expected_ss.is_empty());
    }

    #[test]
    fn test_ml_kem_768_vector_2_field_access() {
        // Access all fields of the second ML-KEM-768 test vector
        let vector = &ml_kem_kat::ML_KEM_768_VECTORS[1];

        assert_eq!(vector.test_name, "ML-KEM-768-KAT-2");
        assert!(!vector.seed.is_empty());
        assert!(!vector.expected_pk.is_empty());
        assert!(!vector.expected_sk.is_empty());
        assert!(!vector.expected_ct.is_empty());
        assert!(!vector.expected_ss.is_empty());
    }

    #[test]
    fn test_ml_kem_1024_vector_1_field_access() {
        // Access all fields of the first ML-KEM-1024 test vector
        let vector = &ml_kem_kat::ML_KEM_1024_VECTORS[0];

        assert_eq!(vector.test_name, "ML-KEM-1024-KAT-1");
        assert!(!vector.seed.is_empty());
        assert!(!vector.expected_pk.is_empty());
        assert!(!vector.expected_sk.is_empty());
        assert!(!vector.expected_ct.is_empty());
        assert!(!vector.expected_ss.is_empty());
    }

    #[test]
    fn test_ml_kem_1024_vector_2_field_access() {
        // Access all fields of the second ML-KEM-1024 test vector
        let vector = &ml_kem_kat::ML_KEM_1024_VECTORS[1];

        assert_eq!(vector.test_name, "ML-KEM-1024-KAT-2");
        assert!(!vector.seed.is_empty());
        assert!(!vector.expected_pk.is_empty());
        assert!(!vector.expected_sk.is_empty());
        assert!(!vector.expected_ct.is_empty());
        assert!(!vector.expected_ss.is_empty());
    }
}

// ============================================================================
// Test Vector Decoding Tests
// ============================================================================

mod test_vector_decoding_tests {
    use super::*;

    #[test]
    fn test_ml_kem_512_seed_decoding() {
        // Verify seeds can be decoded correctly
        for vector in ml_kem_kat::ML_KEM_512_VECTORS {
            let result = decode_hex(vector.seed);
            assert!(result.is_ok(), "Failed to decode seed for {}: {:?}", vector.test_name, result);
            let seed_bytes = result.unwrap();
            // ML-KEM seeds should be 64 bytes (512 bits)
            assert_eq!(seed_bytes.len(), 64, "Seed length mismatch for {}", vector.test_name);
        }
    }

    #[test]
    fn test_ml_kem_768_seed_decoding() {
        // Verify seeds can be decoded correctly
        for vector in ml_kem_kat::ML_KEM_768_VECTORS {
            let result = decode_hex(vector.seed);
            assert!(result.is_ok(), "Failed to decode seed for {}: {:?}", vector.test_name, result);
            let seed_bytes = result.unwrap();
            // ML-KEM seeds should be 64 bytes (512 bits)
            assert_eq!(seed_bytes.len(), 64, "Seed length mismatch for {}", vector.test_name);
        }
    }

    #[test]
    fn test_ml_kem_1024_seed_decoding() {
        // Verify seeds can be decoded correctly
        for vector in ml_kem_kat::ML_KEM_1024_VECTORS {
            let result = decode_hex(vector.seed);
            assert!(result.is_ok(), "Failed to decode seed for {}: {:?}", vector.test_name, result);
            let seed_bytes = result.unwrap();
            // ML-KEM seeds should be 64 bytes (512 bits)
            assert_eq!(seed_bytes.len(), 64, "Seed length mismatch for {}", vector.test_name);
        }
    }

    #[test]
    fn test_ml_kem_512_expected_ss_decoding() {
        // Verify expected shared secrets can be decoded
        for vector in ml_kem_kat::ML_KEM_512_VECTORS {
            let result = decode_hex(vector.expected_ss);
            assert!(
                result.is_ok(),
                "Failed to decode expected_ss for {}: {:?}",
                vector.test_name,
                result
            );
            let ss_bytes = result.unwrap();
            // ML-KEM shared secrets should be 32 bytes (256 bits)
            assert_eq!(
                ss_bytes.len(),
                32,
                "Shared secret length mismatch for {}",
                vector.test_name
            );
        }
    }

    #[test]
    fn test_ml_kem_768_expected_ss_decoding() {
        // Verify expected shared secrets can be decoded
        for vector in ml_kem_kat::ML_KEM_768_VECTORS {
            let result = decode_hex(vector.expected_ss);
            assert!(
                result.is_ok(),
                "Failed to decode expected_ss for {}: {:?}",
                vector.test_name,
                result
            );
            let ss_bytes = result.unwrap();
            // ML-KEM shared secrets should be 32 bytes (256 bits)
            assert_eq!(
                ss_bytes.len(),
                32,
                "Shared secret length mismatch for {}",
                vector.test_name
            );
        }
    }

    #[test]
    fn test_ml_kem_1024_expected_ss_decoding() {
        // Verify expected shared secrets can be decoded
        for vector in ml_kem_kat::ML_KEM_1024_VECTORS {
            let result = decode_hex(vector.expected_ss);
            assert!(
                result.is_ok(),
                "Failed to decode expected_ss for {}: {:?}",
                vector.test_name,
                result
            );
            let ss_bytes = result.unwrap();
            // ML-KEM shared secrets should be 32 bytes (256 bits)
            assert_eq!(
                ss_bytes.len(),
                32,
                "Shared secret length mismatch for {}",
                vector.test_name
            );
        }
    }
}

// ============================================================================
// Public KAT Runner Function Tests
// ============================================================================

mod kat_runner_function_tests {
    use super::*;

    #[test]
    fn test_run_ml_kem_512_kat_success() {
        // Test the main ML-KEM-512 KAT runner function
        let result = ml_kem_kat::run_ml_kem_512_kat();
        assert!(result.is_ok(), "ML-KEM-512 KAT failed: {:?}", result);
    }

    #[test]
    fn test_run_ml_kem_768_kat_success() {
        // Test the main ML-KEM-768 KAT runner function
        let result = ml_kem_kat::run_ml_kem_768_kat();
        assert!(result.is_ok(), "ML-KEM-768 KAT failed: {:?}", result);
    }

    #[test]
    fn test_run_ml_kem_1024_kat_success() {
        // Test the main ML-KEM-1024 KAT runner function
        let result = ml_kem_kat::run_ml_kem_1024_kat();
        assert!(result.is_ok(), "ML-KEM-1024 KAT failed: {:?}", result);
    }

    #[test]
    fn test_all_ml_kem_variants_succeed() {
        // Run all variants and ensure they all pass
        let results = vec![
            ("ML-KEM-512", ml_kem_kat::run_ml_kem_512_kat()),
            ("ML-KEM-768", ml_kem_kat::run_ml_kem_768_kat()),
            ("ML-KEM-1024", ml_kem_kat::run_ml_kem_1024_kat()),
        ];

        for (name, result) in results {
            assert!(result.is_ok(), "{} KAT failed: {:?}", name, result);
        }
    }
}

// ============================================================================
// Integration with KatRunner Tests
// ============================================================================

mod kat_runner_integration_tests {
    use super::*;

    #[test]
    fn test_ml_kem_512_with_kat_runner() {
        let mut runner = KatRunner::new();
        runner.run_test("ML-KEM-512-Full", "ML-KEM-512", || ml_kem_kat::run_ml_kem_512_kat());

        let summary = runner.finish();
        assert!(summary.all_passed(), "ML-KEM-512 KAT runner failed");
        assert_eq!(summary.total, 1);
        assert_eq!(summary.passed, 1);
    }

    #[test]
    fn test_ml_kem_768_with_kat_runner() {
        let mut runner = KatRunner::new();
        runner.run_test("ML-KEM-768-Full", "ML-KEM-768", || ml_kem_kat::run_ml_kem_768_kat());

        let summary = runner.finish();
        assert!(summary.all_passed(), "ML-KEM-768 KAT runner failed");
        assert_eq!(summary.total, 1);
        assert_eq!(summary.passed, 1);
    }

    #[test]
    fn test_ml_kem_1024_with_kat_runner() {
        let mut runner = KatRunner::new();
        runner.run_test("ML-KEM-1024-Full", "ML-KEM-1024", || ml_kem_kat::run_ml_kem_1024_kat());

        let summary = runner.finish();
        assert!(summary.all_passed(), "ML-KEM-1024 KAT runner failed");
        assert_eq!(summary.total, 1);
        assert_eq!(summary.passed, 1);
    }

    #[test]
    fn test_all_ml_kem_variants_with_kat_runner() {
        let mut runner = KatRunner::new();

        runner.run_test("ML-KEM-512", "ML-KEM", || ml_kem_kat::run_ml_kem_512_kat());
        runner.run_test("ML-KEM-768", "ML-KEM", || ml_kem_kat::run_ml_kem_768_kat());
        runner.run_test("ML-KEM-1024", "ML-KEM", || ml_kem_kat::run_ml_kem_1024_kat());

        let summary = runner.finish();
        assert!(summary.all_passed(), "ML-KEM full suite failed");
        assert_eq!(summary.total, 3);
        assert_eq!(summary.passed, 3);
        assert_eq!(summary.failed, 0);
    }

    #[test]
    fn test_ml_kem_runner_records_execution_time() {
        let mut runner = KatRunner::new();
        runner.run_test("ML-KEM-512-Timed", "ML-KEM-512", || ml_kem_kat::run_ml_kem_512_kat());

        let summary = runner.finish();
        // Execution time should be positive (crypto operations take measurable time)
        assert!(
            summary.results[0].execution_time_us > 0,
            "Expected positive execution time, got {}",
            summary.results[0].execution_time_us
        );
    }
}

// ============================================================================
// Test Vector Count and Structure Tests
// ============================================================================

mod vector_structure_tests {
    use super::*;

    #[test]
    fn test_ml_kem_512_vector_count() {
        assert_eq!(ml_kem_kat::ML_KEM_512_VECTORS.len(), 2, "Expected 2 ML-KEM-512 test vectors");
    }

    #[test]
    fn test_ml_kem_768_vector_count() {
        assert_eq!(ml_kem_kat::ML_KEM_768_VECTORS.len(), 2, "Expected 2 ML-KEM-768 test vectors");
    }

    #[test]
    fn test_ml_kem_1024_vector_count() {
        assert_eq!(ml_kem_kat::ML_KEM_1024_VECTORS.len(), 2, "Expected 2 ML-KEM-1024 test vectors");
    }

    #[test]
    fn test_total_ml_kem_vector_count() {
        let total = ml_kem_kat::ML_KEM_512_VECTORS.len()
            + ml_kem_kat::ML_KEM_768_VECTORS.len()
            + ml_kem_kat::ML_KEM_1024_VECTORS.len();

        assert_eq!(total, 6, "Expected 6 total ML-KEM test vectors");
    }

    #[test]
    fn test_vector_names_are_unique() {
        let mut names = Vec::new();

        for vector in ml_kem_kat::ML_KEM_512_VECTORS {
            names.push(vector.test_name);
        }
        for vector in ml_kem_kat::ML_KEM_768_VECTORS {
            names.push(vector.test_name);
        }
        for vector in ml_kem_kat::ML_KEM_1024_VECTORS {
            names.push(vector.test_name);
        }

        // Check for duplicates
        let original_len = names.len();
        names.sort();
        names.dedup();
        assert_eq!(names.len(), original_len, "Test vector names should be unique");
    }

    #[test]
    fn test_ml_kem_512_vector_names_follow_convention() {
        for vector in ml_kem_kat::ML_KEM_512_VECTORS {
            assert!(
                vector.test_name.starts_with("ML-KEM-512"),
                "Vector name '{}' should start with 'ML-KEM-512'",
                vector.test_name
            );
        }
    }

    #[test]
    fn test_ml_kem_768_vector_names_follow_convention() {
        for vector in ml_kem_kat::ML_KEM_768_VECTORS {
            assert!(
                vector.test_name.starts_with("ML-KEM-768"),
                "Vector name '{}' should start with 'ML-KEM-768'",
                vector.test_name
            );
        }
    }

    #[test]
    fn test_ml_kem_1024_vector_names_follow_convention() {
        for vector in ml_kem_kat::ML_KEM_1024_VECTORS {
            assert!(
                vector.test_name.starts_with("ML-KEM-1024"),
                "Vector name '{}' should start with 'ML-KEM-1024'",
                vector.test_name
            );
        }
    }
}

// ============================================================================
// Hex String Validation Tests
// ============================================================================

mod hex_validation_tests {
    use super::*;

    #[test]
    fn test_all_ml_kem_512_hex_strings_valid() {
        for vector in ml_kem_kat::ML_KEM_512_VECTORS {
            // Each field should be valid hex
            assert!(decode_hex(vector.seed).is_ok(), "Invalid seed hex in {}", vector.test_name);
            assert!(
                decode_hex(vector.expected_pk).is_ok(),
                "Invalid expected_pk hex in {}",
                vector.test_name
            );
            assert!(
                decode_hex(vector.expected_sk).is_ok(),
                "Invalid expected_sk hex in {}",
                vector.test_name
            );
            assert!(
                decode_hex(vector.expected_ct).is_ok(),
                "Invalid expected_ct hex in {}",
                vector.test_name
            );
            assert!(
                decode_hex(vector.expected_ss).is_ok(),
                "Invalid expected_ss hex in {}",
                vector.test_name
            );
        }
    }

    #[test]
    fn test_all_ml_kem_768_hex_strings_valid() {
        for vector in ml_kem_kat::ML_KEM_768_VECTORS {
            // Each field should be valid hex
            assert!(decode_hex(vector.seed).is_ok(), "Invalid seed hex in {}", vector.test_name);
            assert!(
                decode_hex(vector.expected_pk).is_ok(),
                "Invalid expected_pk hex in {}",
                vector.test_name
            );
            assert!(
                decode_hex(vector.expected_sk).is_ok(),
                "Invalid expected_sk hex in {}",
                vector.test_name
            );
            assert!(
                decode_hex(vector.expected_ct).is_ok(),
                "Invalid expected_ct hex in {}",
                vector.test_name
            );
            assert!(
                decode_hex(vector.expected_ss).is_ok(),
                "Invalid expected_ss hex in {}",
                vector.test_name
            );
        }
    }

    #[test]
    fn test_all_ml_kem_1024_hex_strings_valid() {
        for vector in ml_kem_kat::ML_KEM_1024_VECTORS {
            // Each field should be valid hex
            assert!(decode_hex(vector.seed).is_ok(), "Invalid seed hex in {}", vector.test_name);
            assert!(
                decode_hex(vector.expected_pk).is_ok(),
                "Invalid expected_pk hex in {}",
                vector.test_name
            );
            assert!(
                decode_hex(vector.expected_sk).is_ok(),
                "Invalid expected_sk hex in {}",
                vector.test_name
            );
            assert!(
                decode_hex(vector.expected_ct).is_ok(),
                "Invalid expected_ct hex in {}",
                vector.test_name
            );
            assert!(
                decode_hex(vector.expected_ss).is_ok(),
                "Invalid expected_ss hex in {}",
                vector.test_name
            );
        }
    }

    #[test]
    fn test_seed_hex_has_correct_length() {
        // Seeds should be 64 bytes = 128 hex characters
        for vector in ml_kem_kat::ML_KEM_512_VECTORS {
            let seed = vector.seed.replace(char::is_whitespace, "");
            assert_eq!(
                seed.len(),
                128,
                "Seed hex length should be 128 chars for {}",
                vector.test_name
            );
        }
        for vector in ml_kem_kat::ML_KEM_768_VECTORS {
            let seed = vector.seed.replace(char::is_whitespace, "");
            assert_eq!(
                seed.len(),
                128,
                "Seed hex length should be 128 chars for {}",
                vector.test_name
            );
        }
        for vector in ml_kem_kat::ML_KEM_1024_VECTORS {
            let seed = vector.seed.replace(char::is_whitespace, "");
            assert_eq!(
                seed.len(),
                128,
                "Seed hex length should be 128 chars for {}",
                vector.test_name
            );
        }
    }

    #[test]
    fn test_shared_secret_hex_has_correct_length() {
        // Shared secrets should be 32 bytes = 64 hex characters
        for vector in ml_kem_kat::ML_KEM_512_VECTORS {
            let ss = vector.expected_ss.replace(char::is_whitespace, "");
            assert_eq!(
                ss.len(),
                64,
                "Shared secret hex length should be 64 chars for {}",
                vector.test_name
            );
        }
        for vector in ml_kem_kat::ML_KEM_768_VECTORS {
            let ss = vector.expected_ss.replace(char::is_whitespace, "");
            assert_eq!(
                ss.len(),
                64,
                "Shared secret hex length should be 64 chars for {}",
                vector.test_name
            );
        }
        for vector in ml_kem_kat::ML_KEM_1024_VECTORS {
            let ss = vector.expected_ss.replace(char::is_whitespace, "");
            assert_eq!(
                ss.len(),
                64,
                "Shared secret hex length should be 64 chars for {}",
                vector.test_name
            );
        }
    }
}

// ============================================================================
// Error Handling Tests
// ============================================================================

mod error_handling_tests {
    use super::*;

    #[test]
    fn test_nist_kat_error_test_failed_format() {
        let error = NistKatError::TestFailed {
            algorithm: "ML-KEM-512".to_string(),
            test_name: "Test-1".to_string(),
            message: "Shared secrets do not match".to_string(),
        };

        let error_string = error.to_string();
        assert!(error_string.contains("ML-KEM-512"));
        assert!(error_string.contains("Test-1"));
        assert!(error_string.contains("Shared secrets do not match"));
    }

    #[test]
    fn test_nist_kat_error_implementation_error_format() {
        let error = NistKatError::ImplementationError("KeyGen failed".to_string());
        let error_string = error.to_string();
        assert!(error_string.contains("KeyGen failed"));
    }

    #[test]
    fn test_nist_kat_error_hex_error_format() {
        let error = NistKatError::HexError("Invalid hex character".to_string());
        let error_string = error.to_string();
        assert!(error_string.contains("Invalid hex character"));
    }

    #[test]
    fn test_decode_hex_invalid_character_error() {
        let result = decode_hex("xyz");
        assert!(result.is_err());
        match result {
            Err(NistKatError::HexError(msg)) => {
                assert!(!msg.is_empty(), "Error message should not be empty");
            }
            _ => panic!("Expected HexError"),
        }
    }

    #[test]
    fn test_decode_hex_odd_length_error() {
        let result = decode_hex("abc");
        assert!(result.is_err());
        match result {
            Err(NistKatError::HexError(_)) => {}
            _ => panic!("Expected HexError for odd length"),
        }
    }
}

// ============================================================================
// KEM Operation Tests
// ============================================================================

mod kem_operation_tests {
    use super::*;

    #[test]
    fn test_ml_kem_512_keygen_encaps_decaps_cycle() {
        // This test exercises the full KEM cycle that run_ml_kem_512_kat uses
        let result = ml_kem_kat::run_ml_kem_512_kat();
        assert!(result.is_ok(), "ML-KEM-512 cycle failed: {:?}", result);
    }

    #[test]
    fn test_ml_kem_768_keygen_encaps_decaps_cycle() {
        // This test exercises the full KEM cycle that run_ml_kem_768_kat uses
        let result = ml_kem_kat::run_ml_kem_768_kat();
        assert!(result.is_ok(), "ML-KEM-768 cycle failed: {:?}", result);
    }

    #[test]
    fn test_ml_kem_1024_keygen_encaps_decaps_cycle() {
        // This test exercises the full KEM cycle that run_ml_kem_1024_kat uses
        let result = ml_kem_kat::run_ml_kem_1024_kat();
        assert!(result.is_ok(), "ML-KEM-1024 cycle failed: {:?}", result);
    }

    #[test]
    fn test_ml_kem_512_multiple_runs() {
        // Run multiple times to ensure consistency
        for i in 0..3 {
            let result = ml_kem_kat::run_ml_kem_512_kat();
            assert!(result.is_ok(), "ML-KEM-512 run {} failed: {:?}", i, result);
        }
    }

    #[test]
    fn test_ml_kem_768_multiple_runs() {
        // Run multiple times to ensure consistency
        for i in 0..3 {
            let result = ml_kem_kat::run_ml_kem_768_kat();
            assert!(result.is_ok(), "ML-KEM-768 run {} failed: {:?}", i, result);
        }
    }

    #[test]
    fn test_ml_kem_1024_multiple_runs() {
        // Run multiple times to ensure consistency
        for i in 0..3 {
            let result = ml_kem_kat::run_ml_kem_1024_kat();
            assert!(result.is_ok(), "ML-KEM-1024 run {} failed: {:?}", i, result);
        }
    }
}

// ============================================================================
// Seed Pattern Tests
// ============================================================================

mod seed_pattern_tests {
    use super::*;

    #[test]
    fn test_ml_kem_512_zero_seed_vector() {
        // First vector uses all-zeros seed
        let vector = &ml_kem_kat::ML_KEM_512_VECTORS[0];
        let seed = decode_hex(vector.seed).expect("Seed decode failed");

        // Should be 64 bytes
        assert_eq!(seed.len(), 64);
        // All zeros
        assert!(seed.iter().all(|&b| b == 0), "First vector seed should be all zeros");
    }

    #[test]
    fn test_ml_kem_512_all_ones_seed_vector() {
        // Second vector uses all-ones seed (0xFF)
        let vector = &ml_kem_kat::ML_KEM_512_VECTORS[1];
        let seed = decode_hex(vector.seed).expect("Seed decode failed");

        // Should be 64 bytes
        assert_eq!(seed.len(), 64);
        // All 0xFF
        assert!(seed.iter().all(|&b| b == 0xFF), "Second vector seed should be all 0xFF");
    }

    #[test]
    fn test_ml_kem_768_zero_seed_vector() {
        // First vector uses all-zeros seed
        let vector = &ml_kem_kat::ML_KEM_768_VECTORS[0];
        let seed = decode_hex(vector.seed).expect("Seed decode failed");

        assert_eq!(seed.len(), 64);
        assert!(seed.iter().all(|&b| b == 0), "First vector seed should be all zeros");
    }

    #[test]
    fn test_ml_kem_768_incremental_seed_vector() {
        // Second vector uses incremental pattern
        let vector = &ml_kem_kat::ML_KEM_768_VECTORS[1];
        let seed = decode_hex(vector.seed).expect("Seed decode failed");

        assert_eq!(seed.len(), 64);
        // Check first few bytes are incrementing
        assert_eq!(seed[0], 0x01);
        assert_eq!(seed[1], 0x02);
        assert_eq!(seed[2], 0x03);
    }

    #[test]
    fn test_ml_kem_1024_zero_seed_vector() {
        // First vector uses all-zeros seed
        let vector = &ml_kem_kat::ML_KEM_1024_VECTORS[0];
        let seed = decode_hex(vector.seed).expect("Seed decode failed");

        assert_eq!(seed.len(), 64);
        assert!(seed.iter().all(|&b| b == 0), "First vector seed should be all zeros");
    }

    #[test]
    fn test_ml_kem_1024_repeating_seed_vector() {
        // Second vector uses 0xAA repeating pattern
        let vector = &ml_kem_kat::ML_KEM_1024_VECTORS[1];
        let seed = decode_hex(vector.seed).expect("Seed decode failed");

        assert_eq!(seed.len(), 64);
        assert!(seed.iter().all(|&b| b == 0xAA), "Second vector seed should be all 0xAA");
    }
}

// ============================================================================
// Field Completeness Tests
// ============================================================================

mod field_completeness_tests {
    use super::*;

    #[test]
    fn test_ml_kem_512_all_fields_present() {
        for vector in ml_kem_kat::ML_KEM_512_VECTORS {
            // All fields must be non-empty
            assert!(!vector.test_name.is_empty(), "test_name is empty");
            assert!(!vector.seed.is_empty(), "seed is empty for {}", vector.test_name);
            assert!(
                !vector.expected_pk.is_empty(),
                "expected_pk is empty for {}",
                vector.test_name
            );
            assert!(
                !vector.expected_sk.is_empty(),
                "expected_sk is empty for {}",
                vector.test_name
            );
            assert!(
                !vector.expected_ct.is_empty(),
                "expected_ct is empty for {}",
                vector.test_name
            );
            assert!(
                !vector.expected_ss.is_empty(),
                "expected_ss is empty for {}",
                vector.test_name
            );
        }
    }

    #[test]
    fn test_ml_kem_768_all_fields_present() {
        for vector in ml_kem_kat::ML_KEM_768_VECTORS {
            assert!(!vector.test_name.is_empty(), "test_name is empty");
            assert!(!vector.seed.is_empty(), "seed is empty for {}", vector.test_name);
            assert!(
                !vector.expected_pk.is_empty(),
                "expected_pk is empty for {}",
                vector.test_name
            );
            assert!(
                !vector.expected_sk.is_empty(),
                "expected_sk is empty for {}",
                vector.test_name
            );
            assert!(
                !vector.expected_ct.is_empty(),
                "expected_ct is empty for {}",
                vector.test_name
            );
            assert!(
                !vector.expected_ss.is_empty(),
                "expected_ss is empty for {}",
                vector.test_name
            );
        }
    }

    #[test]
    fn test_ml_kem_1024_all_fields_present() {
        for vector in ml_kem_kat::ML_KEM_1024_VECTORS {
            assert!(!vector.test_name.is_empty(), "test_name is empty");
            assert!(!vector.seed.is_empty(), "seed is empty for {}", vector.test_name);
            assert!(
                !vector.expected_pk.is_empty(),
                "expected_pk is empty for {}",
                vector.test_name
            );
            assert!(
                !vector.expected_sk.is_empty(),
                "expected_sk is empty for {}",
                vector.test_name
            );
            assert!(
                !vector.expected_ct.is_empty(),
                "expected_ct is empty for {}",
                vector.test_name
            );
            assert!(
                !vector.expected_ss.is_empty(),
                "expected_ss is empty for {}",
                vector.test_name
            );
        }
    }
}

// ============================================================================
// Boundary and Edge Case Tests
// ============================================================================

mod boundary_tests {
    use super::*;

    #[test]
    fn test_first_and_last_vectors_512() {
        // Test first vector
        let first = &ml_kem_kat::ML_KEM_512_VECTORS[0];
        assert_eq!(first.test_name, "ML-KEM-512-KAT-1");

        // Test last vector
        let last_idx = ml_kem_kat::ML_KEM_512_VECTORS.len() - 1;
        let last = &ml_kem_kat::ML_KEM_512_VECTORS[last_idx];
        assert_eq!(last.test_name, "ML-KEM-512-KAT-2");
    }

    #[test]
    fn test_first_and_last_vectors_768() {
        let first = &ml_kem_kat::ML_KEM_768_VECTORS[0];
        assert_eq!(first.test_name, "ML-KEM-768-KAT-1");

        let last_idx = ml_kem_kat::ML_KEM_768_VECTORS.len() - 1;
        let last = &ml_kem_kat::ML_KEM_768_VECTORS[last_idx];
        assert_eq!(last.test_name, "ML-KEM-768-KAT-2");
    }

    #[test]
    fn test_first_and_last_vectors_1024() {
        let first = &ml_kem_kat::ML_KEM_1024_VECTORS[0];
        assert_eq!(first.test_name, "ML-KEM-1024-KAT-1");

        let last_idx = ml_kem_kat::ML_KEM_1024_VECTORS.len() - 1;
        let last = &ml_kem_kat::ML_KEM_1024_VECTORS[last_idx];
        assert_eq!(last.test_name, "ML-KEM-1024-KAT-2");
    }

    #[test]
    fn test_iterating_all_512_vectors() {
        let mut count = 0;
        for vector in ml_kem_kat::ML_KEM_512_VECTORS {
            let _ = vector.test_name;
            let _ = vector.seed;
            count += 1;
        }
        assert_eq!(count, 2);
    }

    #[test]
    fn test_iterating_all_768_vectors() {
        let mut count = 0;
        for vector in ml_kem_kat::ML_KEM_768_VECTORS {
            let _ = vector.test_name;
            let _ = vector.seed;
            count += 1;
        }
        assert_eq!(count, 2);
    }

    #[test]
    fn test_iterating_all_1024_vectors() {
        let mut count = 0;
        for vector in ml_kem_kat::ML_KEM_1024_VECTORS {
            let _ = vector.test_name;
            let _ = vector.seed;
            count += 1;
        }
        assert_eq!(count, 2);
    }
}

// ============================================================================
// Performance Sanity Tests
// ============================================================================

mod performance_tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn test_ml_kem_512_completes_in_reasonable_time() {
        let start = Instant::now();
        let result = ml_kem_kat::run_ml_kem_512_kat();
        let duration = start.elapsed();

        assert!(result.is_ok());
        // Should complete in under 5 seconds
        assert!(duration.as_secs() < 5, "ML-KEM-512 took too long: {:?}", duration);
    }

    #[test]
    fn test_ml_kem_768_completes_in_reasonable_time() {
        let start = Instant::now();
        let result = ml_kem_kat::run_ml_kem_768_kat();
        let duration = start.elapsed();

        assert!(result.is_ok());
        assert!(duration.as_secs() < 5, "ML-KEM-768 took too long: {:?}", duration);
    }

    #[test]
    fn test_ml_kem_1024_completes_in_reasonable_time() {
        let start = Instant::now();
        let result = ml_kem_kat::run_ml_kem_1024_kat();
        let duration = start.elapsed();

        assert!(result.is_ok());
        assert!(duration.as_secs() < 5, "ML-KEM-1024 took too long: {:?}", duration);
    }
}

// ============================================================================
// Security Level Tests
// ============================================================================

mod security_level_tests {
    use super::*;

    #[test]
    fn test_ml_kem_512_is_security_level_1() {
        // ML-KEM-512 provides NIST Security Level 1 (128-bit classical)
        // Verify we have test vectors for this security level
        assert!(!ml_kem_kat::ML_KEM_512_VECTORS.is_empty());

        // Run the KAT to validate the implementation
        let result = ml_kem_kat::run_ml_kem_512_kat();
        assert!(result.is_ok(), "Security Level 1 (ML-KEM-512) validation failed");
    }

    #[test]
    fn test_ml_kem_768_is_security_level_3() {
        // ML-KEM-768 provides NIST Security Level 3 (192-bit classical)
        assert!(!ml_kem_kat::ML_KEM_768_VECTORS.is_empty());

        let result = ml_kem_kat::run_ml_kem_768_kat();
        assert!(result.is_ok(), "Security Level 3 (ML-KEM-768) validation failed");
    }

    #[test]
    fn test_ml_kem_1024_is_security_level_5() {
        // ML-KEM-1024 provides NIST Security Level 5 (256-bit classical)
        assert!(!ml_kem_kat::ML_KEM_1024_VECTORS.is_empty());

        let result = ml_kem_kat::run_ml_kem_1024_kat();
        assert!(result.is_ok(), "Security Level 5 (ML-KEM-1024) validation failed");
    }

    #[test]
    fn test_all_security_levels_covered() {
        // Ensure we have coverage for all three NIST security levels
        let levels = vec![
            ("Level 1", ml_kem_kat::ML_KEM_512_VECTORS.len()),
            ("Level 3", ml_kem_kat::ML_KEM_768_VECTORS.len()),
            ("Level 5", ml_kem_kat::ML_KEM_1024_VECTORS.len()),
        ];

        for (level, count) in levels {
            assert!(count > 0, "No test vectors for {}", level);
        }
    }
}
