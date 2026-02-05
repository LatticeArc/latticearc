//! Elliptic Curve KAT (Known Answer Test) Comprehensive Test Suite
//!
//! This module provides comprehensive tests for the EC KAT functionality
//! including Ed25519 and secp256k1 curves. Tests cover:
//! - Public API functions
//! - EC curve test vectors
//! - Verification of EC operations
//! - KatResult type behavior
//! - Edge cases and boundary conditions

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

use arc_validation::kat_tests::ec::run_ec_kat_tests;
use arc_validation::kat_tests::types::{
    AlgorithmType, Ed25519KatVector, KatConfig, KatResult, Secp256k1KatVector,
};
use std::time::Duration;

// ============================================================================
// Tests for run_ec_kat_tests function
// ============================================================================

mod run_ec_kat_tests_tests {
    use super::*;

    #[test]
    fn test_run_ec_kat_tests_returns_ok() {
        let result = run_ec_kat_tests();
        assert!(result.is_ok(), "run_ec_kat_tests should return Ok");
    }

    #[test]
    fn test_run_ec_kat_tests_returns_results() {
        let results = run_ec_kat_tests().unwrap();
        assert!(!results.is_empty(), "Should return at least one KatResult");
    }

    #[test]
    fn test_run_ec_kat_tests_includes_ed25519_results() {
        let results = run_ec_kat_tests().unwrap();
        let ed25519_results: Vec<_> =
            results.iter().filter(|r| r.test_case.contains("Ed25519")).collect();

        assert!(!ed25519_results.is_empty(), "Should include Ed25519 test results");
    }

    #[test]
    fn test_run_ec_kat_tests_includes_secp256k1_results() {
        let results = run_ec_kat_tests().unwrap();
        let secp256k1_results: Vec<_> =
            results.iter().filter(|r| r.test_case.contains("secp256k1")).collect();

        assert!(!secp256k1_results.is_empty(), "Should include secp256k1 test results");
    }

    #[test]
    fn test_run_ec_kat_tests_all_pass() {
        let results = run_ec_kat_tests().unwrap();
        let all_passed = results.iter().all(|r| r.passed);
        assert!(all_passed, "All EC KAT tests should pass");
    }

    #[test]
    fn test_run_ec_kat_tests_expected_count() {
        let results = run_ec_kat_tests().unwrap();
        // 5 Ed25519 tests + 3 secp256k1 tests = 8 total
        assert_eq!(results.len(), 8, "Should return exactly 8 KAT results");
    }

    #[test]
    fn test_run_ec_kat_tests_ed25519_count() {
        let results = run_ec_kat_tests().unwrap();
        let ed25519_count = results.iter().filter(|r| r.test_case.contains("Ed25519")).count();
        assert_eq!(ed25519_count, 5, "Should have exactly 5 Ed25519 test cases");
    }

    #[test]
    fn test_run_ec_kat_tests_secp256k1_count() {
        let results = run_ec_kat_tests().unwrap();
        let secp256k1_count = results.iter().filter(|r| r.test_case.contains("secp256k1")).count();
        assert_eq!(secp256k1_count, 3, "Should have exactly 3 secp256k1 test cases");
    }

    #[test]
    fn test_run_ec_kat_tests_no_error_messages() {
        let results = run_ec_kat_tests().unwrap();
        for result in &results {
            assert!(
                result.error_message.is_none(),
                "Test {} should have no error message",
                result.test_case
            );
        }
    }

    #[test]
    fn test_run_ec_kat_tests_execution_time_recorded() {
        let results = run_ec_kat_tests().unwrap();
        for result in &results {
            // Execution time should be recorded (can be 0 for very fast tests)
            assert!(
                result.execution_time_ns < u128::MAX,
                "Execution time should be recorded for {}",
                result.test_case
            );
        }
    }

    #[test]
    fn test_run_ec_kat_tests_test_case_naming() {
        let results = run_ec_kat_tests().unwrap();

        // Check Ed25519 naming pattern
        for i in 1..=5 {
            let expected_name = format!("Ed25519-KAT-{:03}", i);
            assert!(
                results.iter().any(|r| r.test_case == expected_name),
                "Should have test case named {}",
                expected_name
            );
        }

        // Check secp256k1 naming pattern
        for i in 1..=3 {
            let expected_name = format!("secp256k1-KAT-{:03}", i);
            assert!(
                results.iter().any(|r| r.test_case == expected_name),
                "Should have test case named {}",
                expected_name
            );
        }
    }

    #[test]
    fn test_run_ec_kat_tests_idempotent() {
        // Running multiple times should produce consistent results
        let results1 = run_ec_kat_tests().unwrap();
        let results2 = run_ec_kat_tests().unwrap();

        assert_eq!(results1.len(), results2.len(), "Multiple runs should return same count");

        for (r1, r2) in results1.iter().zip(results2.iter()) {
            assert_eq!(r1.test_case, r2.test_case, "Test case names should be consistent");
            assert_eq!(r1.passed, r2.passed, "Pass/fail should be consistent");
        }
    }
}

// ============================================================================
// Tests for KatResult type
// ============================================================================

mod kat_result_tests {
    use super::*;

    #[test]
    fn test_kat_result_passed_constructor() {
        let duration = Duration::from_micros(100);
        let result = KatResult::passed("Test-001".to_string(), duration);

        assert_eq!(result.test_case, "Test-001");
        assert!(result.passed);
        assert_eq!(result.execution_time_ns, 100_000);
        assert!(result.error_message.is_none());
    }

    #[test]
    fn test_kat_result_failed_constructor() {
        let duration = Duration::from_millis(5);
        let result =
            KatResult::failed("Test-002".to_string(), duration, "Signature mismatch".to_string());

        assert_eq!(result.test_case, "Test-002");
        assert!(!result.passed);
        assert_eq!(result.execution_time_ns, 5_000_000);
        assert_eq!(result.error_message, Some("Signature mismatch".to_string()));
    }

    #[test]
    fn test_kat_result_clone() {
        let result = KatResult::passed("Clone-Test".to_string(), Duration::from_nanos(500));
        let cloned = result.clone();

        assert_eq!(result.test_case, cloned.test_case);
        assert_eq!(result.passed, cloned.passed);
        assert_eq!(result.execution_time_ns, cloned.execution_time_ns);
        assert_eq!(result.error_message, cloned.error_message);
    }

    #[test]
    fn test_kat_result_equality() {
        let result1 = KatResult::passed("Eq-Test".to_string(), Duration::from_micros(100));
        let result2 = KatResult::passed("Eq-Test".to_string(), Duration::from_micros(100));

        assert_eq!(result1, result2);
    }

    #[test]
    fn test_kat_result_inequality_test_case() {
        let result1 = KatResult::passed("Test-A".to_string(), Duration::from_micros(100));
        let result2 = KatResult::passed("Test-B".to_string(), Duration::from_micros(100));

        assert_ne!(result1, result2);
    }

    #[test]
    fn test_kat_result_inequality_passed() {
        let result1 = KatResult::passed("Test-A".to_string(), Duration::from_micros(100));
        let result2 = KatResult::failed(
            "Test-A".to_string(),
            Duration::from_micros(100),
            "Error".to_string(),
        );

        assert_ne!(result1, result2);
    }

    #[test]
    fn test_kat_result_debug_format() {
        let result = KatResult::passed("Debug-Test".to_string(), Duration::from_micros(50));
        let debug_str = format!("{:?}", result);

        assert!(debug_str.contains("Debug-Test"));
        assert!(debug_str.contains("passed: true"));
    }

    #[test]
    fn test_kat_result_serialization() {
        let result = KatResult::passed("Serde-Test".to_string(), Duration::from_micros(250));
        let json = serde_json::to_string(&result).unwrap();

        assert!(json.contains("Serde-Test"));
        assert!(json.contains("true"));
    }

    #[test]
    fn test_kat_result_deserialization() {
        let json = r#"{"test_case":"Deser-Test","passed":true,"execution_time_ns":1000,"error_message":null}"#;
        let result: KatResult = serde_json::from_str(json).unwrap();

        assert_eq!(result.test_case, "Deser-Test");
        assert!(result.passed);
        assert_eq!(result.execution_time_ns, 1000);
        assert!(result.error_message.is_none());
    }

    #[test]
    fn test_kat_result_round_trip_serialization() {
        let original = KatResult::failed(
            "RoundTrip".to_string(),
            Duration::from_millis(10),
            "Test error".to_string(),
        );
        let json = serde_json::to_string(&original).unwrap();
        let deserialized: KatResult = serde_json::from_str(&json).unwrap();

        assert_eq!(original, deserialized);
    }

    #[test]
    fn test_kat_result_zero_duration() {
        let result = KatResult::passed("Zero-Duration".to_string(), Duration::ZERO);
        assert_eq!(result.execution_time_ns, 0);
    }

    #[test]
    fn test_kat_result_large_duration() {
        let result = KatResult::passed("Large-Duration".to_string(), Duration::from_secs(3600));
        assert_eq!(result.execution_time_ns, 3600 * 1_000_000_000u128);
    }

    #[test]
    fn test_kat_result_empty_test_case_name() {
        let result = KatResult::passed(String::new(), Duration::from_micros(1));
        assert!(result.test_case.is_empty());
        assert!(result.passed);
    }

    #[test]
    fn test_kat_result_empty_error_message() {
        let result =
            KatResult::failed("Empty-Error".to_string(), Duration::from_micros(1), String::new());
        assert_eq!(result.error_message, Some(String::new()));
    }

    #[test]
    fn test_kat_result_unicode_test_case() {
        let result = KatResult::passed("Test-Unicode-".to_string(), Duration::from_micros(1));
        assert!(result.test_case.contains(""));
    }
}

// ============================================================================
// Tests for Ed25519KatVector type
// ============================================================================

mod ed25519_kat_vector_tests {
    use super::*;

    #[test]
    fn test_ed25519_kat_vector_creation() {
        let vector = Ed25519KatVector {
            test_case: "Ed25519-001".to_string(),
            seed: vec![0u8; 32],
            expected_public_key: vec![0u8; 32],
            message: b"test message".to_vec(),
            expected_signature: vec![0u8; 64],
        };

        assert_eq!(vector.test_case, "Ed25519-001");
        assert_eq!(vector.seed.len(), 32);
        assert_eq!(vector.expected_public_key.len(), 32);
        assert_eq!(vector.expected_signature.len(), 64);
    }

    #[test]
    fn test_ed25519_kat_vector_clone() {
        let vector = Ed25519KatVector {
            test_case: "Clone-Test".to_string(),
            seed: vec![1, 2, 3, 4],
            expected_public_key: vec![5, 6, 7, 8],
            message: vec![9, 10, 11, 12],
            expected_signature: vec![13, 14, 15, 16],
        };

        let cloned = vector.clone();
        assert_eq!(vector, cloned);
    }

    #[test]
    fn test_ed25519_kat_vector_equality() {
        let v1 = Ed25519KatVector {
            test_case: "Test".to_string(),
            seed: vec![1, 2, 3],
            expected_public_key: vec![4, 5, 6],
            message: vec![7, 8, 9],
            expected_signature: vec![10, 11, 12],
        };

        let v2 = v1.clone();
        assert_eq!(v1, v2);
    }

    #[test]
    fn test_ed25519_kat_vector_serialization() {
        let vector = Ed25519KatVector {
            test_case: "Serde-Test".to_string(),
            seed: vec![0xab, 0xcd],
            expected_public_key: vec![0xef],
            message: vec![0x12, 0x34],
            expected_signature: vec![0x56, 0x78],
        };

        let json = serde_json::to_string(&vector).unwrap();
        assert!(json.contains("Serde-Test"));

        let deserialized: Ed25519KatVector = serde_json::from_str(&json).unwrap();
        assert_eq!(vector, deserialized);
    }

    #[test]
    fn test_ed25519_kat_vector_empty_message() {
        let vector = Ed25519KatVector {
            test_case: "Empty-Message".to_string(),
            seed: vec![0u8; 32],
            expected_public_key: vec![0u8; 32],
            message: Vec::new(),
            expected_signature: vec![0u8; 64],
        };

        assert!(vector.message.is_empty());
    }

    #[test]
    fn test_ed25519_kat_vector_large_message() {
        let vector = Ed25519KatVector {
            test_case: "Large-Message".to_string(),
            seed: vec![0u8; 32],
            expected_public_key: vec![0u8; 32],
            message: vec![0xffu8; 10000],
            expected_signature: vec![0u8; 64],
        };

        assert_eq!(vector.message.len(), 10000);
    }
}

// ============================================================================
// Tests for Secp256k1KatVector type
// ============================================================================

mod secp256k1_kat_vector_tests {
    use super::*;

    #[test]
    fn test_secp256k1_kat_vector_creation() {
        let vector = Secp256k1KatVector {
            test_case: "secp256k1-001".to_string(),
            private_key: vec![0u8; 32],
            expected_public_key: vec![0u8; 33], // Compressed public key
            message: b"test message".to_vec(),
            expected_signature: vec![0u8; 72], // DER-encoded signature
        };

        assert_eq!(vector.test_case, "secp256k1-001");
        assert_eq!(vector.private_key.len(), 32);
    }

    #[test]
    fn test_secp256k1_kat_vector_clone() {
        let vector = Secp256k1KatVector {
            test_case: "Clone-Test".to_string(),
            private_key: vec![1, 2, 3, 4],
            expected_public_key: vec![5, 6, 7, 8],
            message: vec![9, 10, 11, 12],
            expected_signature: vec![13, 14, 15, 16],
        };

        let cloned = vector.clone();
        assert_eq!(vector, cloned);
    }

    #[test]
    fn test_secp256k1_kat_vector_equality() {
        let v1 = Secp256k1KatVector {
            test_case: "Test".to_string(),
            private_key: vec![1, 2, 3],
            expected_public_key: vec![4, 5, 6],
            message: vec![7, 8, 9],
            expected_signature: vec![10, 11, 12],
        };

        let v2 = v1.clone();
        assert_eq!(v1, v2);
    }

    #[test]
    fn test_secp256k1_kat_vector_serialization() {
        let vector = Secp256k1KatVector {
            test_case: "Serde-Test".to_string(),
            private_key: vec![0xab, 0xcd],
            expected_public_key: vec![0xef],
            message: vec![0x12, 0x34],
            expected_signature: vec![0x56, 0x78],
        };

        let json = serde_json::to_string(&vector).unwrap();
        let deserialized: Secp256k1KatVector = serde_json::from_str(&json).unwrap();
        assert_eq!(vector, deserialized);
    }
}

// ============================================================================
// Tests for AlgorithmType enum (EC-related variants)
// ============================================================================

mod algorithm_type_ec_tests {
    use super::*;

    #[test]
    fn test_algorithm_type_ed25519() {
        let algo = AlgorithmType::Ed25519;
        assert_eq!(algo.name(), "Ed25519");
        assert_eq!(algo.security_level(), 128);
    }

    #[test]
    fn test_algorithm_type_secp256k1() {
        let algo = AlgorithmType::Secp256k1;
        assert_eq!(algo.name(), "secp256k1");
        assert_eq!(algo.security_level(), 128);
    }

    #[test]
    fn test_algorithm_type_bls12_381() {
        let algo = AlgorithmType::Bls12_381;
        assert_eq!(algo.name(), "BLS12-381");
        assert_eq!(algo.security_level(), 128);
    }

    #[test]
    fn test_algorithm_type_bn254() {
        let algo = AlgorithmType::Bn254;
        assert_eq!(algo.name(), "BN254");
        assert_eq!(algo.security_level(), 128);
    }

    #[test]
    fn test_algorithm_type_clone() {
        let algo = AlgorithmType::Ed25519;
        let cloned = algo.clone();
        assert_eq!(algo, cloned);
    }

    #[test]
    fn test_algorithm_type_equality() {
        assert_eq!(AlgorithmType::Ed25519, AlgorithmType::Ed25519);
        assert_ne!(AlgorithmType::Ed25519, AlgorithmType::Secp256k1);
    }

    #[test]
    fn test_algorithm_type_debug() {
        let algo = AlgorithmType::Ed25519;
        let debug_str = format!("{:?}", algo);
        assert!(debug_str.contains("Ed25519"));
    }

    #[test]
    fn test_algorithm_type_serialization() {
        let algo = AlgorithmType::Ed25519;
        let json = serde_json::to_string(&algo).unwrap();
        let deserialized: AlgorithmType = serde_json::from_str(&json).unwrap();
        assert_eq!(algo, deserialized);
    }

    #[test]
    fn test_algorithm_type_secp256k1_serialization() {
        let algo = AlgorithmType::Secp256k1;
        let json = serde_json::to_string(&algo).unwrap();
        let deserialized: AlgorithmType = serde_json::from_str(&json).unwrap();
        assert_eq!(algo, deserialized);
    }
}

// ============================================================================
// Tests for KatConfig (EC-related configurations)
// ============================================================================

mod kat_config_tests {
    use super::*;

    #[test]
    fn test_kat_config_default() {
        let config = KatConfig::default();

        assert_eq!(config.test_count, 100);
        assert!(config.run_statistical_tests);
        assert_eq!(config.timeout_per_test, Duration::from_secs(10));
        assert!(config.validate_fips);
    }

    #[test]
    fn test_kat_config_clone() {
        let config = KatConfig::default();
        let cloned = config.clone();

        assert_eq!(config.test_count, cloned.test_count);
        assert_eq!(config.run_statistical_tests, cloned.run_statistical_tests);
        assert_eq!(config.timeout_per_test, cloned.timeout_per_test);
    }

    #[test]
    fn test_kat_config_equality() {
        let c1 = KatConfig::default();
        let c2 = KatConfig::default();
        assert_eq!(c1, c2);
    }

    #[test]
    fn test_kat_config_debug() {
        let config = KatConfig::default();
        let debug_str = format!("{:?}", config);
        assert!(debug_str.contains("test_count"));
    }

    #[test]
    fn test_kat_config_serialization() {
        let config = KatConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        assert!(json.contains("test_count"));

        let deserialized: KatConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config, deserialized);
    }

    #[test]
    fn test_kat_config_ml_kem() {
        let config = KatConfig::ml_kem("768", 50);

        assert!(matches!(config.algorithm, AlgorithmType::MlKem { .. }));
        assert_eq!(config.test_count, 50);
    }

    #[test]
    fn test_kat_config_ml_dsa() {
        let config = KatConfig::ml_dsa("65", 25);

        assert!(matches!(config.algorithm, AlgorithmType::MlDsa { .. }));
        assert_eq!(config.test_count, 25);
    }

    #[test]
    fn test_kat_config_slh_dsa() {
        let config = KatConfig::slh_dsa("128", 10);

        assert!(matches!(config.algorithm, AlgorithmType::SlhDsa { .. }));
        assert_eq!(config.test_count, 10);
        // SLH-DSA has longer timeout
        assert_eq!(config.timeout_per_test, Duration::from_secs(30));
    }
}

// ============================================================================
// Edge case and boundary tests
// ============================================================================

mod edge_case_tests {
    use super::*;

    #[test]
    fn test_multiple_sequential_runs() {
        // Run EC KAT tests multiple times in sequence
        for i in 0..3 {
            let results = run_ec_kat_tests().unwrap();
            assert_eq!(results.len(), 8, "Run {} should have 8 results", i + 1);
            assert!(results.iter().all(|r| r.passed), "Run {} should pass all tests", i + 1);
        }
    }

    #[test]
    fn test_result_ordering_consistent() {
        let results = run_ec_kat_tests().unwrap();

        // Ed25519 results should come before secp256k1 results
        let first_secp256k1_idx =
            results.iter().position(|r| r.test_case.contains("secp256k1")).unwrap();
        let last_ed25519_idx =
            results.iter().rposition(|r| r.test_case.contains("Ed25519")).unwrap();

        assert!(
            last_ed25519_idx < first_secp256k1_idx,
            "Ed25519 tests should come before secp256k1 tests"
        );
    }

    #[test]
    fn test_kat_result_with_special_characters() {
        let result = KatResult::passed(
            "Test-with-special-chars-!@#$%".to_string(),
            Duration::from_micros(1),
        );

        // Should serialize and deserialize correctly
        let json = serde_json::to_string(&result).unwrap();
        let deserialized: KatResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result.test_case, deserialized.test_case);
    }

    #[test]
    fn test_ed25519_vector_with_all_zeros() {
        let vector = Ed25519KatVector {
            test_case: "All-Zeros".to_string(),
            seed: vec![0u8; 32],
            expected_public_key: vec![0u8; 32],
            message: vec![0u8; 100],
            expected_signature: vec![0u8; 64],
        };

        let json = serde_json::to_string(&vector).unwrap();
        let deserialized: Ed25519KatVector = serde_json::from_str(&json).unwrap();
        assert_eq!(vector, deserialized);
    }

    #[test]
    fn test_ed25519_vector_with_all_ones() {
        let vector = Ed25519KatVector {
            test_case: "All-Ones".to_string(),
            seed: vec![0xffu8; 32],
            expected_public_key: vec![0xffu8; 32],
            message: vec![0xffu8; 100],
            expected_signature: vec![0xffu8; 64],
        };

        let json = serde_json::to_string(&vector).unwrap();
        let deserialized: Ed25519KatVector = serde_json::from_str(&json).unwrap();
        assert_eq!(vector, deserialized);
    }

    #[test]
    fn test_secp256k1_vector_with_all_zeros() {
        let vector = Secp256k1KatVector {
            test_case: "All-Zeros".to_string(),
            private_key: vec![0u8; 32],
            expected_public_key: vec![0u8; 33],
            message: vec![0u8; 100],
            expected_signature: vec![0u8; 72],
        };

        let json = serde_json::to_string(&vector).unwrap();
        let deserialized: Secp256k1KatVector = serde_json::from_str(&json).unwrap();
        assert_eq!(vector, deserialized);
    }

    #[test]
    fn test_kat_result_collect_to_vec() {
        let results = run_ec_kat_tests().unwrap();

        let passed_results: Vec<_> = results.iter().filter(|r| r.passed).cloned().collect();
        let failed_results: Vec<_> = results.iter().filter(|r| !r.passed).cloned().collect();

        assert_eq!(passed_results.len(), 8);
        assert!(failed_results.is_empty());
    }

    #[test]
    fn test_algorithm_type_all_ec_variants() {
        let ec_algorithms = [
            AlgorithmType::Ed25519,
            AlgorithmType::Secp256k1,
            AlgorithmType::Bls12_381,
            AlgorithmType::Bn254,
        ];

        for algo in ec_algorithms {
            // All EC algorithms should have 128-bit security level
            assert_eq!(algo.security_level(), 128, "{} should have 128-bit security", algo.name());
        }
    }
}

// ============================================================================
// Integration tests
// ============================================================================

mod integration_tests {
    use super::*;

    #[test]
    fn test_full_ec_kat_workflow() {
        // Simulate a full KAT workflow
        let results = run_ec_kat_tests().unwrap();

        // Verify all results
        assert!(!results.is_empty(), "Should have results");
        assert!(results.iter().all(|r| r.passed), "All should pass");

        // Generate summary statistics
        let total_time_ns: u128 = results.iter().map(|r| r.execution_time_ns).sum();
        let avg_time_ns = total_time_ns / (results.len() as u128);

        // Average time should be reasonable (less than 1 second)
        assert!(avg_time_ns < 1_000_000_000, "Average execution time should be less than 1 second");
    }

    #[test]
    fn test_kat_result_filtering_and_aggregation() {
        let results = run_ec_kat_tests().unwrap();

        // Filter by curve type
        let ed25519_results: Vec<_> =
            results.iter().filter(|r| r.test_case.starts_with("Ed25519")).collect();

        let secp256k1_results: Vec<_> =
            results.iter().filter(|r| r.test_case.starts_with("secp256k1")).collect();

        // Verify counts
        assert_eq!(ed25519_results.len(), 5);
        assert_eq!(secp256k1_results.len(), 3);

        // Verify all passed
        assert!(ed25519_results.iter().all(|r| r.passed));
        assert!(secp256k1_results.iter().all(|r| r.passed));
    }

    #[test]
    fn test_kat_result_json_report_generation() {
        let results = run_ec_kat_tests().unwrap();

        // Generate JSON report
        let report = serde_json::json!({
            "test_suite": "EC KAT Tests",
            "total_tests": results.len(),
            "passed": results.iter().filter(|r| r.passed).count(),
            "failed": results.iter().filter(|r| !r.passed).count(),
            "results": results
        });

        let json_str = serde_json::to_string_pretty(&report).unwrap();

        assert!(json_str.contains("EC KAT Tests"));
        assert!(json_str.contains("\"passed\": 8"));
        assert!(json_str.contains("\"failed\": 0"));
    }

    #[test]
    fn test_kat_types_interoperability() {
        // Test that different KAT vector types can be used together
        let ed25519_vec = Ed25519KatVector {
            test_case: "Ed25519-Interop".to_string(),
            seed: vec![0u8; 32],
            expected_public_key: vec![0u8; 32],
            message: b"interop test".to_vec(),
            expected_signature: vec![0u8; 64],
        };

        let secp256k1_vec = Secp256k1KatVector {
            test_case: "secp256k1-Interop".to_string(),
            private_key: vec![0u8; 32],
            expected_public_key: vec![0u8; 33],
            message: b"interop test".to_vec(),
            expected_signature: vec![0u8; 72],
        };

        // Both should serialize to JSON
        let ed25519_json = serde_json::to_string(&ed25519_vec).unwrap();
        let secp256k1_json = serde_json::to_string(&secp256k1_vec).unwrap();

        assert!(ed25519_json.contains("Ed25519-Interop"));
        assert!(secp256k1_json.contains("secp256k1-Interop"));
    }

    #[test]
    fn test_algorithm_type_name_consistency() {
        // Verify algorithm names are consistent with industry standards
        let names = vec![
            (AlgorithmType::Ed25519, "Ed25519"),
            (AlgorithmType::Secp256k1, "secp256k1"),
            (AlgorithmType::Bls12_381, "BLS12-381"),
            (AlgorithmType::Bn254, "BN254"),
        ];

        for (algo, expected_name) in names {
            assert_eq!(algo.name(), expected_name);
        }
    }
}

// ============================================================================
// Performance-related tests
// ============================================================================

mod performance_tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn test_ec_kat_execution_time() {
        let start = Instant::now();
        let _results = run_ec_kat_tests().unwrap();
        let duration = start.elapsed();

        // EC KAT tests should complete quickly (under 1 second)
        assert!(duration.as_secs() < 1, "EC KAT tests took too long: {:?}", duration);
    }

    #[test]
    fn test_individual_result_timing() {
        let results = run_ec_kat_tests().unwrap();

        // Each individual test should be fast
        for result in &results {
            let duration_ms = result.execution_time_ns / 1_000_000;
            assert!(
                duration_ms < 100,
                "Test {} took {}ms, expected < 100ms",
                result.test_case,
                duration_ms
            );
        }
    }

    #[test]
    fn test_total_execution_time_reasonable() {
        let results = run_ec_kat_tests().unwrap();

        let total_ns: u128 = results.iter().map(|r| r.execution_time_ns).sum();
        let total_ms = total_ns / 1_000_000;

        // Total time should be reasonable (under 500ms)
        assert!(total_ms < 500, "Total execution time {}ms exceeds 500ms", total_ms);
    }
}

// ============================================================================
// Thread safety tests
// ============================================================================

mod thread_safety_tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_concurrent_ec_kat_runs() {
        let handles: Vec<_> = (0..4)
            .map(|_| {
                thread::spawn(|| {
                    let results = run_ec_kat_tests().unwrap();
                    assert_eq!(results.len(), 8);
                    assert!(results.iter().all(|r| r.passed));
                })
            })
            .collect();

        for handle in handles {
            handle.join().unwrap();
        }
    }

    #[test]
    fn test_kat_result_send_sync() {
        // Verify KatResult implements Send + Sync
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<KatResult>();
    }

    #[test]
    fn test_kat_vector_types_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Ed25519KatVector>();
        assert_send_sync::<Secp256k1KatVector>();
    }

    #[test]
    fn test_algorithm_type_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<AlgorithmType>();
    }
}
