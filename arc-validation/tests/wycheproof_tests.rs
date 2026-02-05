//! Comprehensive tests for arc-validation wycheproof module
//!
//! This test suite covers:
//! - WycheproofError enum and all variants
//! - WycheproofResults struct and all methods
//! - Error handling paths
//! - Edge cases and boundary conditions
//! - Display and Debug trait implementations

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

use arc_validation::wycheproof::{WycheproofError, WycheproofResults};
use std::error::Error;

// ============================================================================
// WycheproofError Tests
// ============================================================================

mod wycheproof_error_tests {
    use super::*;

    #[test]
    fn test_load_error_creation() {
        let error = WycheproofError::LoadError("Failed to load test vectors".to_string());
        assert!(matches!(error, WycheproofError::LoadError(_)));
    }

    #[test]
    fn test_load_error_display() {
        let error = WycheproofError::LoadError("Network timeout".to_string());
        let display = format!("{}", error);
        assert!(display.contains("Failed to load test vectors"));
        assert!(display.contains("Network timeout"));
    }

    #[test]
    fn test_load_error_debug() {
        let error = WycheproofError::LoadError("File not found".to_string());
        let debug = format!("{:?}", error);
        assert!(debug.contains("LoadError"));
        assert!(debug.contains("File not found"));
    }

    #[test]
    fn test_test_failed_creation() {
        let error =
            WycheproofError::TestFailed { tc_id: 42, message: "Decryption failed".to_string() };
        assert!(matches!(error, WycheproofError::TestFailed { tc_id: 42, .. }));
    }

    #[test]
    fn test_test_failed_display() {
        let error =
            WycheproofError::TestFailed { tc_id: 123, message: "Invalid ciphertext".to_string() };
        let display = format!("{}", error);
        assert!(display.contains("Test case 123 failed"));
        assert!(display.contains("Invalid ciphertext"));
    }

    #[test]
    fn test_test_failed_debug() {
        let error =
            WycheproofError::TestFailed { tc_id: 999, message: "Signature mismatch".to_string() };
        let debug = format!("{:?}", error);
        assert!(debug.contains("TestFailed"));
        assert!(debug.contains("tc_id: 999"));
        assert!(debug.contains("Signature mismatch"));
    }

    #[test]
    fn test_unexpected_result_creation() {
        let error = WycheproofError::UnexpectedResult {
            tc_id: 55,
            expected: "valid".to_string(),
            actual: "invalid".to_string(),
        };
        assert!(matches!(error, WycheproofError::UnexpectedResult { tc_id: 55, .. }));
    }

    #[test]
    fn test_unexpected_result_display() {
        let error = WycheproofError::UnexpectedResult {
            tc_id: 77,
            expected: "success".to_string(),
            actual: "failure".to_string(),
        };
        let display = format!("{}", error);
        assert!(display.contains("Unexpected result for test 77"));
        assert!(display.contains("expected success"));
        assert!(display.contains("got failure"));
    }

    #[test]
    fn test_unexpected_result_debug() {
        let error = WycheproofError::UnexpectedResult {
            tc_id: 88,
            expected: "pass".to_string(),
            actual: "fail".to_string(),
        };
        let debug = format!("{:?}", error);
        assert!(debug.contains("UnexpectedResult"));
        assert!(debug.contains("tc_id: 88"));
        assert!(debug.contains("expected"));
        assert!(debug.contains("actual"));
    }

    #[test]
    fn test_error_is_std_error() {
        let error = WycheproofError::LoadError("test".to_string());
        // Verify it implements std::error::Error
        let _: &dyn Error = &error;
    }

    #[test]
    fn test_load_error_with_empty_message() {
        let error = WycheproofError::LoadError(String::new());
        let display = format!("{}", error);
        assert!(display.contains("Failed to load test vectors"));
    }

    #[test]
    fn test_test_failed_with_zero_tc_id() {
        let error = WycheproofError::TestFailed { tc_id: 0, message: "Test zero".to_string() };
        let display = format!("{}", error);
        assert!(display.contains("Test case 0 failed"));
    }

    #[test]
    fn test_test_failed_with_max_tc_id() {
        let error =
            WycheproofError::TestFailed { tc_id: u32::MAX, message: "Max test".to_string() };
        let display = format!("{}", error);
        assert!(display.contains(&u32::MAX.to_string()));
    }

    #[test]
    fn test_unexpected_result_with_empty_strings() {
        let error = WycheproofError::UnexpectedResult {
            tc_id: 1,
            expected: String::new(),
            actual: String::new(),
        };
        let display = format!("{}", error);
        assert!(display.contains("Unexpected result for test 1"));
    }

    #[test]
    fn test_load_error_with_special_characters() {
        let error = WycheproofError::LoadError("Error: <>&\"'".to_string());
        let display = format!("{}", error);
        assert!(display.contains("<>&\"'"));
    }

    #[test]
    fn test_test_failed_with_unicode_message() {
        let error = WycheproofError::TestFailed { tc_id: 100, message: "Unicode test".to_string() };
        let display = format!("{}", error);
        assert!(display.contains("Unicode"));
    }

    #[test]
    fn test_unexpected_result_with_long_strings() {
        let long_expected = "a".repeat(1000);
        let long_actual = "b".repeat(1000);
        let error = WycheproofError::UnexpectedResult {
            tc_id: 1,
            expected: long_expected.clone(),
            actual: long_actual.clone(),
        };
        let display = format!("{}", error);
        assert!(display.contains(&long_expected));
        assert!(display.contains(&long_actual));
    }
}

// ============================================================================
// WycheproofResults Constructor Tests
// ============================================================================

mod wycheproof_results_constructor_tests {
    use super::*;

    #[test]
    fn test_new_creates_default_instance() {
        let results = WycheproofResults::new();
        assert_eq!(results.total, 0);
        assert_eq!(results.passed, 0);
        assert_eq!(results.failed, 0);
        assert_eq!(results.skipped, 0);
        assert!(results.failures.is_empty());
    }

    #[test]
    fn test_default_creates_same_as_new() {
        let from_new = WycheproofResults::new();
        let from_default = WycheproofResults::default();

        assert_eq!(from_new.total, from_default.total);
        assert_eq!(from_new.passed, from_default.passed);
        assert_eq!(from_new.failed, from_default.failed);
        assert_eq!(from_new.skipped, from_default.skipped);
        assert_eq!(from_new.failures.len(), from_default.failures.len());
    }

    #[test]
    fn test_debug_output() {
        let results = WycheproofResults::new();
        let debug = format!("{:?}", results);
        assert!(debug.contains("WycheproofResults"));
        assert!(debug.contains("total"));
        assert!(debug.contains("passed"));
        assert!(debug.contains("failed"));
        assert!(debug.contains("skipped"));
        assert!(debug.contains("failures"));
    }
}

// ============================================================================
// WycheproofResults all_passed Tests
// ============================================================================

mod wycheproof_results_all_passed_tests {
    use super::*;

    #[test]
    fn test_all_passed_with_new_instance() {
        let results = WycheproofResults::new();
        assert!(results.all_passed());
    }

    #[test]
    fn test_all_passed_after_only_passes() {
        let mut results = WycheproofResults::new();
        results.add_pass();
        results.add_pass();
        results.add_pass();
        assert!(results.all_passed());
    }

    #[test]
    fn test_all_passed_with_one_failure() {
        let mut results = WycheproofResults::new();
        results.add_pass();
        results.add_failure("test failed".to_string());
        assert!(!results.all_passed());
    }

    #[test]
    fn test_all_passed_with_only_failures() {
        let mut results = WycheproofResults::new();
        results.add_failure("failure 1".to_string());
        results.add_failure("failure 2".to_string());
        assert!(!results.all_passed());
    }

    #[test]
    fn test_all_passed_with_skips_only() {
        let mut results = WycheproofResults::new();
        results.add_skip();
        results.add_skip();
        assert!(results.all_passed());
    }

    #[test]
    fn test_all_passed_with_passes_and_skips() {
        let mut results = WycheproofResults::new();
        results.add_pass();
        results.add_skip();
        results.add_pass();
        assert!(results.all_passed());
    }

    #[test]
    fn test_all_passed_with_mixed_results() {
        let mut results = WycheproofResults::new();
        results.add_pass();
        results.add_skip();
        results.add_failure("one failure".to_string());
        assert!(!results.all_passed());
    }
}

// ============================================================================
// WycheproofResults add_pass Tests
// ============================================================================

mod wycheproof_results_add_pass_tests {
    use super::*;

    #[test]
    fn test_add_pass_increments_total() {
        let mut results = WycheproofResults::new();
        assert_eq!(results.total, 0);
        results.add_pass();
        assert_eq!(results.total, 1);
    }

    #[test]
    fn test_add_pass_increments_passed() {
        let mut results = WycheproofResults::new();
        assert_eq!(results.passed, 0);
        results.add_pass();
        assert_eq!(results.passed, 1);
    }

    #[test]
    fn test_add_pass_does_not_increment_failed() {
        let mut results = WycheproofResults::new();
        results.add_pass();
        assert_eq!(results.failed, 0);
    }

    #[test]
    fn test_add_pass_does_not_increment_skipped() {
        let mut results = WycheproofResults::new();
        results.add_pass();
        assert_eq!(results.skipped, 0);
    }

    #[test]
    fn test_add_pass_does_not_add_failures() {
        let mut results = WycheproofResults::new();
        results.add_pass();
        assert!(results.failures.is_empty());
    }

    #[test]
    fn test_add_pass_multiple_times() {
        let mut results = WycheproofResults::new();
        for _ in 0..100 {
            results.add_pass();
        }
        assert_eq!(results.total, 100);
        assert_eq!(results.passed, 100);
        assert_eq!(results.failed, 0);
        assert_eq!(results.skipped, 0);
    }
}

// ============================================================================
// WycheproofResults add_failure Tests
// ============================================================================

mod wycheproof_results_add_failure_tests {
    use super::*;

    #[test]
    fn test_add_failure_increments_total() {
        let mut results = WycheproofResults::new();
        assert_eq!(results.total, 0);
        results.add_failure("error".to_string());
        assert_eq!(results.total, 1);
    }

    #[test]
    fn test_add_failure_increments_failed() {
        let mut results = WycheproofResults::new();
        assert_eq!(results.failed, 0);
        results.add_failure("error".to_string());
        assert_eq!(results.failed, 1);
    }

    #[test]
    fn test_add_failure_does_not_increment_passed() {
        let mut results = WycheproofResults::new();
        results.add_failure("error".to_string());
        assert_eq!(results.passed, 0);
    }

    #[test]
    fn test_add_failure_does_not_increment_skipped() {
        let mut results = WycheproofResults::new();
        results.add_failure("error".to_string());
        assert_eq!(results.skipped, 0);
    }

    #[test]
    fn test_add_failure_adds_to_failures_vec() {
        let mut results = WycheproofResults::new();
        results.add_failure("test error message".to_string());
        assert_eq!(results.failures.len(), 1);
        assert_eq!(results.failures[0], "test error message");
    }

    #[test]
    fn test_add_failure_multiple_times() {
        let mut results = WycheproofResults::new();
        results.add_failure("error 1".to_string());
        results.add_failure("error 2".to_string());
        results.add_failure("error 3".to_string());
        assert_eq!(results.total, 3);
        assert_eq!(results.failed, 3);
        assert_eq!(results.failures.len(), 3);
    }

    #[test]
    fn test_add_failure_with_empty_message() {
        let mut results = WycheproofResults::new();
        results.add_failure(String::new());
        assert_eq!(results.failures.len(), 1);
        assert_eq!(results.failures[0], "");
    }

    #[test]
    fn test_add_failure_with_long_message() {
        let mut results = WycheproofResults::new();
        let long_message = "x".repeat(10000);
        results.add_failure(long_message.clone());
        assert_eq!(results.failures[0], long_message);
    }

    #[test]
    fn test_add_failure_preserves_order() {
        let mut results = WycheproofResults::new();
        results.add_failure("first".to_string());
        results.add_failure("second".to_string());
        results.add_failure("third".to_string());
        assert_eq!(results.failures[0], "first");
        assert_eq!(results.failures[1], "second");
        assert_eq!(results.failures[2], "third");
    }

    #[test]
    fn test_add_failure_with_special_characters() {
        let mut results = WycheproofResults::new();
        results.add_failure("Error: <>&\"'\n\t\\".to_string());
        assert!(results.failures[0].contains("<>&"));
    }
}

// ============================================================================
// WycheproofResults add_skip Tests
// ============================================================================

mod wycheproof_results_add_skip_tests {
    use super::*;

    #[test]
    fn test_add_skip_increments_total() {
        let mut results = WycheproofResults::new();
        assert_eq!(results.total, 0);
        results.add_skip();
        assert_eq!(results.total, 1);
    }

    #[test]
    fn test_add_skip_increments_skipped() {
        let mut results = WycheproofResults::new();
        assert_eq!(results.skipped, 0);
        results.add_skip();
        assert_eq!(results.skipped, 1);
    }

    #[test]
    fn test_add_skip_does_not_increment_passed() {
        let mut results = WycheproofResults::new();
        results.add_skip();
        assert_eq!(results.passed, 0);
    }

    #[test]
    fn test_add_skip_does_not_increment_failed() {
        let mut results = WycheproofResults::new();
        results.add_skip();
        assert_eq!(results.failed, 0);
    }

    #[test]
    fn test_add_skip_does_not_add_failures() {
        let mut results = WycheproofResults::new();
        results.add_skip();
        assert!(results.failures.is_empty());
    }

    #[test]
    fn test_add_skip_multiple_times() {
        let mut results = WycheproofResults::new();
        for _ in 0..50 {
            results.add_skip();
        }
        assert_eq!(results.total, 50);
        assert_eq!(results.skipped, 50);
        assert_eq!(results.passed, 0);
        assert_eq!(results.failed, 0);
    }
}

// ============================================================================
// WycheproofResults Mixed Operations Tests
// ============================================================================

mod wycheproof_results_mixed_operations_tests {
    use super::*;

    #[test]
    fn test_mixed_pass_fail_skip() {
        let mut results = WycheproofResults::new();
        results.add_pass();
        results.add_failure("error".to_string());
        results.add_skip();
        results.add_pass();
        results.add_skip();

        assert_eq!(results.total, 5);
        assert_eq!(results.passed, 2);
        assert_eq!(results.failed, 1);
        assert_eq!(results.skipped, 2);
        assert_eq!(results.failures.len(), 1);
    }

    #[test]
    fn test_total_equals_sum_of_categories() {
        let mut results = WycheproofResults::new();
        for _ in 0..10 {
            results.add_pass();
        }
        for _ in 0..5 {
            results.add_failure(format!("error"));
        }
        for _ in 0..3 {
            results.add_skip();
        }

        assert_eq!(results.total, results.passed + results.failed + results.skipped);
        assert_eq!(results.total, 18);
    }

    #[test]
    fn test_failures_vec_matches_failed_count() {
        let mut results = WycheproofResults::new();
        results.add_failure("error 1".to_string());
        results.add_pass();
        results.add_failure("error 2".to_string());
        results.add_skip();
        results.add_failure("error 3".to_string());

        assert_eq!(results.failed, results.failures.len());
    }

    #[test]
    fn test_large_number_of_operations() {
        let mut results = WycheproofResults::new();

        for i in 0..1000 {
            match i % 3 {
                0 => results.add_pass(),
                1 => results.add_failure(format!("error {}", i)),
                _ => results.add_skip(),
            }
        }

        assert_eq!(results.total, 1000);
        assert_eq!(results.passed, 334);
        assert_eq!(results.failed, 333);
        assert_eq!(results.skipped, 333);
        assert_eq!(results.failures.len(), 333);
    }

    #[test]
    fn test_pass_rate_calculation() {
        let mut results = WycheproofResults::new();
        for _ in 0..80 {
            results.add_pass();
        }
        for _ in 0..20 {
            results.add_failure("error".to_string());
        }

        // Calculate pass rate manually
        let pass_rate = results.passed as f64 / results.total as f64;
        assert!((pass_rate - 0.8).abs() < f64::EPSILON);
    }

    #[test]
    fn test_skip_does_not_affect_all_passed() {
        let mut results = WycheproofResults::new();
        results.add_pass();
        results.add_pass();
        results.add_skip();
        results.add_skip();
        results.add_skip();

        // all_passed should be true because failed is 0
        assert!(results.all_passed());
        assert_eq!(results.skipped, 3);
    }
}

// ============================================================================
// WycheproofResults Field Access Tests
// ============================================================================

mod wycheproof_results_field_access_tests {
    use super::*;

    #[test]
    fn test_direct_field_access_total() {
        let mut results = WycheproofResults::new();
        results.add_pass();
        assert_eq!(results.total, 1);
    }

    #[test]
    fn test_direct_field_access_passed() {
        let mut results = WycheproofResults::new();
        results.add_pass();
        assert_eq!(results.passed, 1);
    }

    #[test]
    fn test_direct_field_access_failed() {
        let mut results = WycheproofResults::new();
        results.add_failure("test".to_string());
        assert_eq!(results.failed, 1);
    }

    #[test]
    fn test_direct_field_access_skipped() {
        let mut results = WycheproofResults::new();
        results.add_skip();
        assert_eq!(results.skipped, 1);
    }

    #[test]
    fn test_direct_field_access_failures() {
        let mut results = WycheproofResults::new();
        results.add_failure("error message".to_string());
        assert_eq!(results.failures[0], "error message");
    }

    #[test]
    fn test_iterate_over_failures() {
        let mut results = WycheproofResults::new();
        results.add_failure("error 1".to_string());
        results.add_failure("error 2".to_string());
        results.add_failure("error 3".to_string());

        let mut count = 0;
        for (i, failure) in results.failures.iter().enumerate() {
            assert!(failure.contains(&format!("error {}", i + 1)));
            count += 1;
        }
        assert_eq!(count, 3);
    }
}

// ============================================================================
// Edge Cases and Boundary Tests
// ============================================================================

mod edge_cases_tests {
    use super::*;

    #[test]
    fn test_zero_tests_all_passed_is_true() {
        let results = WycheproofResults::new();
        // With no tests run, all_passed returns true (no failures)
        assert!(results.all_passed());
    }

    #[test]
    fn test_only_one_failure() {
        let mut results = WycheproofResults::new();
        results.add_failure("single failure".to_string());
        assert!(!results.all_passed());
        assert_eq!(results.total, 1);
    }

    #[test]
    fn test_many_passes_one_failure() {
        let mut results = WycheproofResults::new();
        for _ in 0..10000 {
            results.add_pass();
        }
        results.add_failure("one failure".to_string());

        assert!(!results.all_passed());
        assert_eq!(results.passed, 10000);
        assert_eq!(results.failed, 1);
    }

    #[test]
    fn test_failure_message_with_newlines() {
        let mut results = WycheproofResults::new();
        results.add_failure("Line 1\nLine 2\nLine 3".to_string());
        assert!(results.failures[0].contains("\n"));
    }

    #[test]
    fn test_failure_message_with_tabs() {
        let mut results = WycheproofResults::new();
        results.add_failure("Column1\tColumn2\tColumn3".to_string());
        assert!(results.failures[0].contains("\t"));
    }

    #[test]
    fn test_failures_vec_capacity_growth() {
        let mut results = WycheproofResults::new();
        // Add many failures to test vector growth
        for i in 0..1000 {
            results.add_failure(format!("failure {}", i));
        }
        assert_eq!(results.failures.len(), 1000);
    }
}

// ============================================================================
// Simulation of Real Wycheproof Test Scenarios
// ============================================================================

mod real_scenario_tests {
    use super::*;

    #[test]
    fn test_aes_gcm_like_scenario() {
        let mut results = WycheproofResults::new();

        // Simulate running AES-GCM test vectors
        // Most tests pass, some are skipped (non-standard params), few invalid tests pass correctly
        for _ in 0..100 {
            results.add_pass(); // Valid test passed
        }
        for _ in 0..20 {
            results.add_skip(); // Non-standard key size
        }
        for _ in 0..30 {
            results.add_pass(); // Invalid test correctly rejected
        }

        assert!(results.all_passed());
        assert_eq!(results.total, 150);
        assert_eq!(results.passed, 130);
        assert_eq!(results.skipped, 20);
        assert_eq!(results.failed, 0);
    }

    #[test]
    fn test_ecdsa_like_scenario_with_failures() {
        let mut results = WycheproofResults::new();

        // Simulate ECDSA verification where some tests fail
        for i in 0..50 {
            if i % 10 == 0 {
                results.add_failure(format!("Test {}: signature verification failed", i));
            } else {
                results.add_pass();
            }
        }

        assert!(!results.all_passed());
        assert_eq!(results.total, 50);
        assert_eq!(results.passed, 45);
        assert_eq!(results.failed, 5);

        // Verify failure rate is acceptable (< 5% typically)
        let failure_rate = results.failed as f64 / results.total as f64;
        assert!(failure_rate < 0.15); // 10% failure rate in this scenario
    }

    #[test]
    fn test_chacha20_poly1305_like_scenario() {
        let mut results = WycheproofResults::new();

        // ChaCha20-Poly1305 requires specific key/nonce sizes
        // Most tests run, some skipped for wrong parameters
        for _ in 0..80 {
            results.add_pass();
        }
        for _ in 0..15 {
            results.add_skip(); // Wrong key or nonce size
        }
        for _ in 0..5 {
            results.add_pass(); // Invalid tests correctly fail
        }

        assert!(results.all_passed());
        assert_eq!(results.total, 100);
    }

    #[test]
    fn test_ed25519_like_scenario() {
        let mut results = WycheproofResults::new();

        // EdDSA signature verification
        for _ in 0..200 {
            results.add_pass();
        }
        for _ in 0..10 {
            results.add_skip(); // Invalid public key format
        }

        assert!(results.all_passed());
        assert_eq!(results.total, 210);
    }

    #[test]
    fn test_calculate_statistics() {
        let mut results = WycheproofResults::new();

        for _ in 0..70 {
            results.add_pass();
        }
        for _ in 0..20 {
            results.add_skip();
        }
        for _ in 0..10 {
            results.add_failure("test failure".to_string());
        }

        // Calculate various statistics
        let total_executed = results.passed + results.failed;
        let pass_rate =
            if total_executed > 0 { results.passed as f64 / total_executed as f64 } else { 0.0 };

        assert_eq!(total_executed, 80);
        assert!((pass_rate - 0.875).abs() < f64::EPSILON); // 70/80 = 0.875

        // Skip rate
        let skip_rate = results.skipped as f64 / results.total as f64;
        assert!((skip_rate - 0.2).abs() < f64::EPSILON); // 20/100 = 0.2
    }

    #[test]
    fn test_print_summary() {
        let mut results = WycheproofResults::new();

        for _ in 0..90 {
            results.add_pass();
        }
        for _ in 0..5 {
            results.add_skip();
        }
        for _ in 0..5 {
            results.add_failure("test failure".to_string());
        }

        // Simulate printing a summary (like in the actual tests)
        let summary = format!(
            "Test Results: {}/{} passed, {} skipped, {} failed",
            results.passed, results.total, results.skipped, results.failed
        );

        assert!(summary.contains("90/100 passed"));
        assert!(summary.contains("5 skipped"));
        assert!(summary.contains("5 failed"));
    }
}

// ============================================================================
// WycheproofResults Debug and Clone Tests
// ============================================================================

mod debug_and_clone_tests {
    use super::*;

    #[test]
    fn test_results_debug_empty() {
        let results = WycheproofResults::new();
        let debug = format!("{:?}", results);
        assert!(debug.contains("total: 0"));
        assert!(debug.contains("passed: 0"));
        assert!(debug.contains("failed: 0"));
        assert!(debug.contains("skipped: 0"));
    }

    #[test]
    fn test_results_debug_with_data() {
        let mut results = WycheproofResults::new();
        results.add_pass();
        results.add_pass();
        results.add_failure("error".to_string());
        results.add_skip();

        let debug = format!("{:?}", results);
        assert!(debug.contains("total: 4"));
        assert!(debug.contains("passed: 2"));
        assert!(debug.contains("failed: 1"));
        assert!(debug.contains("skipped: 1"));
    }

    #[test]
    fn test_results_debug_shows_failures() {
        let mut results = WycheproofResults::new();
        results.add_failure("first error".to_string());
        results.add_failure("second error".to_string());

        let debug = format!("{:?}", results);
        assert!(debug.contains("first error"));
        assert!(debug.contains("second error"));
    }
}

// ============================================================================
// Failure Rate Analysis Tests
// ============================================================================

mod failure_rate_tests {
    use super::*;

    #[test]
    fn test_zero_failure_rate() {
        let mut results = WycheproofResults::new();
        for _ in 0..100 {
            results.add_pass();
        }

        let failure_rate = results.failed as f64 / results.total as f64;
        assert_eq!(failure_rate, 0.0);
    }

    #[test]
    fn test_hundred_percent_failure_rate() {
        let mut results = WycheproofResults::new();
        for i in 0..100 {
            results.add_failure(format!("failure {}", i));
        }

        let failure_rate = results.failed as f64 / results.total as f64;
        assert_eq!(failure_rate, 1.0);
    }

    #[test]
    fn test_five_percent_failure_rate() {
        let mut results = WycheproofResults::new();
        for i in 0..100 {
            if i < 5 {
                results.add_failure(format!("failure {}", i));
            } else {
                results.add_pass();
            }
        }

        let failure_rate = results.failed as f64 / results.total as f64;
        assert!((failure_rate - 0.05).abs() < f64::EPSILON);
    }

    #[test]
    fn test_failure_rate_threshold_check() {
        let mut results = WycheproofResults::new();

        // Add results that are just under 5% failure threshold
        for _ in 0..96 {
            results.add_pass();
        }
        for _ in 0..4 {
            results.add_failure("error".to_string());
        }

        let failure_rate = results.failed as f64 / results.total as f64;
        assert!(failure_rate < 0.05, "Failure rate {} should be under 5%", failure_rate);
    }

    #[test]
    fn test_failure_rate_above_threshold() {
        let mut results = WycheproofResults::new();

        for _ in 0..90 {
            results.add_pass();
        }
        for _ in 0..10 {
            results.add_failure("error".to_string());
        }

        let failure_rate = results.failed as f64 / results.total as f64;
        assert!(failure_rate >= 0.05, "Failure rate {} should be at or above 5%", failure_rate);
    }
}

// ============================================================================
// Thread Safety Consideration Tests (Single-threaded)
// ============================================================================

mod single_threaded_mutation_tests {
    use super::*;

    #[test]
    fn test_sequential_mutations() {
        let mut results = WycheproofResults::new();

        // Perform operations in sequence
        results.add_pass();
        assert_eq!(results.total, 1);

        results.add_failure("err".to_string());
        assert_eq!(results.total, 2);

        results.add_skip();
        assert_eq!(results.total, 3);

        // Verify final state
        assert_eq!(results.passed, 1);
        assert_eq!(results.failed, 1);
        assert_eq!(results.skipped, 1);
    }

    #[test]
    fn test_multiple_results_instances() {
        let mut results1 = WycheproofResults::new();
        let mut results2 = WycheproofResults::new();

        results1.add_pass();
        results2.add_failure("error".to_string());

        assert_eq!(results1.total, 1);
        assert_eq!(results2.total, 1);
        assert_eq!(results1.passed, 1);
        assert_eq!(results2.failed, 1);
        assert!(results1.all_passed());
        assert!(!results2.all_passed());
    }
}
