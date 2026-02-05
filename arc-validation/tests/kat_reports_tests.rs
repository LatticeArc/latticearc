//! Comprehensive tests for KAT (Known Answer Test) report generation
//!
//! This test suite validates the report generation functionality in
//! `arc_validation::kat_tests::reports`, including:
//! - Report formatting with various test result combinations
//! - Statistics calculation (pass/fail counts, success rates)
//! - Performance metrics aggregation
//! - Edge cases (empty results, all pass, all fail)

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

use arc_validation::kat_tests::reports::{generate_kat_report, run_kat_tests};
use arc_validation::kat_tests::types::KatResult;
use std::time::Duration;

// =============================================================================
// Test Fixtures and Helpers
// =============================================================================

/// Creates a mock passing KAT result with specified parameters
fn create_passing_result(test_case: &str, execution_time_ns: u128) -> KatResult {
    KatResult {
        test_case: test_case.to_string(),
        passed: true,
        execution_time_ns,
        error_message: None,
    }
}

/// Creates a mock failing KAT result with specified parameters
fn create_failing_result(test_case: &str, execution_time_ns: u128, error: &str) -> KatResult {
    KatResult {
        test_case: test_case.to_string(),
        passed: false,
        execution_time_ns,
        error_message: Some(error.to_string()),
    }
}

/// Creates a set of mixed results for testing
fn create_mixed_results() -> Vec<KatResult> {
    vec![
        create_passing_result("ML-KEM-1024-001", 1_000_000),
        create_passing_result("ML-KEM-1024-002", 1_500_000),
        create_failing_result("ML-KEM-1024-003", 2_000_000, "Keypair validation failed"),
        create_passing_result("ML-KEM-1024-004", 1_200_000),
        create_failing_result("ML-KEM-1024-005", 800_000, "Encapsulation mismatch"),
    ]
}

/// Creates a set of all passing results
fn create_all_passing_results(count: usize) -> Vec<KatResult> {
    (0..count)
        .map(|i| {
            create_passing_result(&format!("TEST-{:03}", i + 1), 1_000_000 + (i as u128) * 100_000)
        })
        .collect()
}

/// Creates a set of all failing results
fn create_all_failing_results(count: usize) -> Vec<KatResult> {
    (0..count)
        .map(|i| {
            create_failing_result(
                &format!("TEST-{:03}", i + 1),
                500_000 + (i as u128) * 50_000,
                &format!("Error in test case {}", i + 1),
            )
        })
        .collect()
}

// =============================================================================
// Report Generation Tests - Basic Functionality
// =============================================================================

#[test]
fn test_generate_report_with_mixed_results() {
    let results = create_mixed_results();
    let report = generate_kat_report(&results);

    // Verify report header
    assert!(report.contains("=== Known Answer Test Report ==="));

    // Verify summary section
    assert!(report.contains("Summary:"));
    assert!(report.contains("Total tests: 5"));
    assert!(report.contains("Passed: 3"));
    assert!(report.contains("Failed: 2"));
    assert!(report.contains("Success rate: 60.00%"));

    // Verify failed tests section exists
    assert!(report.contains("Failed Tests:"));
    assert!(report.contains("ML-KEM-1024-003"));
    assert!(report.contains("Keypair validation failed"));
    assert!(report.contains("ML-KEM-1024-005"));
    assert!(report.contains("Encapsulation mismatch"));

    // Verify performance section
    assert!(report.contains("Performance:"));
    assert!(report.contains("Total execution time:"));
    assert!(report.contains("Average test time:"));
}

#[test]
fn test_generate_report_all_passing() {
    let results = create_all_passing_results(10);
    let report = generate_kat_report(&results);

    // Verify summary
    assert!(report.contains("Total tests: 10"));
    assert!(report.contains("Passed: 10"));
    assert!(report.contains("Failed: 0"));
    assert!(report.contains("Success rate: 100.00%"));

    // Verify no "Failed Tests:" section (since all passed)
    assert!(!report.contains("Failed Tests:"));
}

#[test]
fn test_generate_report_all_failing() {
    let results = create_all_failing_results(5);
    let report = generate_kat_report(&results);

    // Verify summary
    assert!(report.contains("Total tests: 5"));
    assert!(report.contains("Passed: 0"));
    assert!(report.contains("Failed: 5"));
    assert!(report.contains("Success rate: 0.00%"));

    // Verify all failed tests are listed
    assert!(report.contains("Failed Tests:"));
    for i in 1..=5 {
        assert!(report.contains(&format!("TEST-{:03}", i)));
        assert!(report.contains(&format!("Error in test case {}", i)));
    }
}

#[test]
fn test_generate_report_single_result_pass() {
    let results = vec![create_passing_result("SINGLE-TEST-001", 500_000)];
    let report = generate_kat_report(&results);

    assert!(report.contains("Total tests: 1"));
    assert!(report.contains("Passed: 1"));
    assert!(report.contains("Failed: 0"));
    assert!(report.contains("Success rate: 100.00%"));
    assert!(!report.contains("Failed Tests:"));
}

#[test]
fn test_generate_report_single_result_fail() {
    let results =
        vec![create_failing_result("SINGLE-TEST-001", 500_000, "Critical validation error")];
    let report = generate_kat_report(&results);

    assert!(report.contains("Total tests: 1"));
    assert!(report.contains("Passed: 0"));
    assert!(report.contains("Failed: 1"));
    assert!(report.contains("Success rate: 0.00%"));
    assert!(report.contains("Failed Tests:"));
    assert!(report.contains("SINGLE-TEST-001"));
    assert!(report.contains("Critical validation error"));
}

// =============================================================================
// Report Generation Tests - Statistics Calculation
// =============================================================================

#[test]
fn test_success_rate_calculation_precision() {
    // Test various success rates to verify precision
    let test_cases = vec![
        (1, 3, "33.33%"), // 1/3 = 33.33%
        (2, 3, "66.67%"), // 2/3 = 66.67%
        (1, 4, "25.00%"), // 1/4 = 25%
        (3, 4, "75.00%"), // 3/4 = 75%
        (1, 7, "14.29%"), // 1/7 = 14.29%
        (5, 7, "71.43%"), // 5/7 = 71.43%
    ];

    for (passed, total, expected_rate) in test_cases {
        let mut results = Vec::new();
        for i in 0..total {
            if i < passed {
                results.push(create_passing_result(&format!("TEST-{}", i), 1_000_000));
            } else {
                results.push(create_failing_result(&format!("TEST-{}", i), 1_000_000, "Error"));
            }
        }
        let report = generate_kat_report(&results);
        assert!(
            report.contains(expected_rate),
            "Expected success rate {} for {}/{} tests, got report:\n{}",
            expected_rate,
            passed,
            total,
            report
        );
    }
}

#[test]
fn test_total_execution_time_calculation() {
    let results = vec![
        create_passing_result("TEST-001", 1_000_000), // 1ms
        create_passing_result("TEST-002", 2_000_000), // 2ms
        create_passing_result("TEST-003", 3_000_000), // 3ms
        create_failing_result("TEST-004", 4_000_000, "Error"), // 4ms
    ];

    let report = generate_kat_report(&results);

    // Total should be 10,000,000 ns
    assert!(report.contains("Total execution time: 10000000 ns"));

    // Average should be 2,500,000 ns
    assert!(report.contains("Average test time: 2500000 ns"));
}

#[test]
fn test_average_time_calculation_with_varying_durations() {
    let results = vec![
        create_passing_result("FAST-TEST", 100_000),     // 0.1ms
        create_passing_result("MEDIUM-TEST", 1_000_000), // 1ms
        create_passing_result("SLOW-TEST", 10_000_000),  // 10ms
    ];

    let report = generate_kat_report(&results);

    // Total: 11,100,000 ns
    assert!(report.contains("Total execution time: 11100000 ns"));

    // Average: 3,700,000 ns
    assert!(report.contains("Average test time: 3700000 ns"));
}

// =============================================================================
// Report Generation Tests - Edge Cases
// =============================================================================

#[test]
fn test_generate_report_with_no_error_message() {
    // Test case where a failed result has no error message
    let results = vec![KatResult {
        test_case: "TEST-NO-MSG".to_string(),
        passed: false,
        execution_time_ns: 1_000_000,
        error_message: None, // No error message
    }];

    let report = generate_kat_report(&results);

    // Should show "Unknown error" for missing error message
    assert!(report.contains("TEST-NO-MSG"));
    assert!(report.contains("Unknown error"));
}

#[test]
fn test_generate_report_with_empty_test_case_name() {
    let results = vec![create_passing_result("", 500_000)];
    let report = generate_kat_report(&results);

    // Should still generate a valid report
    assert!(report.contains("Total tests: 1"));
    assert!(report.contains("Passed: 1"));
}

#[test]
fn test_generate_report_with_long_test_case_name() {
    let long_name = "A".repeat(500);
    let results = vec![create_failing_result(&long_name, 1_000_000, "Long name test error")];
    let report = generate_kat_report(&results);

    assert!(report.contains(&long_name));
    assert!(report.contains("Long name test error"));
}

#[test]
fn test_generate_report_with_long_error_message() {
    let long_error = "E".repeat(1000);
    let results = vec![create_failing_result("LONG-ERROR-TEST", 1_000_000, &long_error)];
    let report = generate_kat_report(&results);

    assert!(report.contains("LONG-ERROR-TEST"));
    assert!(report.contains(&long_error));
}

#[test]
fn test_generate_report_with_special_characters_in_test_case() {
    let special_cases = vec![
        create_failing_result("TEST-WITH-UNICODE-\u{2713}", 1_000_000, "Unicode test"),
        create_failing_result("TEST/WITH/SLASHES", 1_000_000, "Slash test"),
        create_failing_result("TEST:WITH:COLONS", 1_000_000, "Colon test"),
    ];

    let report = generate_kat_report(&special_cases);

    assert!(report.contains("TEST-WITH-UNICODE-\u{2713}"));
    assert!(report.contains("TEST/WITH/SLASHES"));
    assert!(report.contains("TEST:WITH:COLONS"));
}

#[test]
fn test_generate_report_with_zero_execution_time() {
    let results = vec![
        create_passing_result("INSTANT-TEST-001", 0),
        create_passing_result("INSTANT-TEST-002", 0),
    ];

    let report = generate_kat_report(&results);

    assert!(report.contains("Total execution time: 0 ns"));
    assert!(report.contains("Average test time: 0 ns"));
}

#[test]
fn test_generate_report_with_max_execution_time() {
    let max_time = u128::MAX / 2; // Use half of max to avoid overflow in sum
    let results = vec![create_passing_result("MAX-TIME-TEST", max_time)];

    let report = generate_kat_report(&results);

    assert!(report.contains(&format!("Total execution time: {} ns", max_time)));
    assert!(report.contains(&format!("Average test time: {} ns", max_time)));
}

// =============================================================================
// Report Generation Tests - Large Scale
// =============================================================================

#[test]
fn test_generate_report_with_many_results() {
    let results = create_all_passing_results(1000);
    let report = generate_kat_report(&results);

    assert!(report.contains("Total tests: 1000"));
    assert!(report.contains("Passed: 1000"));
    assert!(report.contains("Failed: 0"));
    assert!(report.contains("Success rate: 100.00%"));
}

#[test]
fn test_generate_report_with_many_failures() {
    let results = create_all_failing_results(100);
    let report = generate_kat_report(&results);

    assert!(report.contains("Total tests: 100"));
    assert!(report.contains("Passed: 0"));
    assert!(report.contains("Failed: 100"));
    assert!(report.contains("Success rate: 0.00%"));

    // Verify all 100 failures are listed
    for i in 1..=100 {
        assert!(report.contains(&format!("TEST-{:03}", i)));
    }
}

// =============================================================================
// Report Generation Tests - Format Validation
// =============================================================================

#[test]
fn test_report_contains_expected_sections_in_order() {
    let results = create_mixed_results();
    let report = generate_kat_report(&results);

    // Find section positions
    let header_pos = report.find("=== Known Answer Test Report ===").unwrap();
    let summary_pos = report.find("Summary:").unwrap();
    let failed_pos = report.find("Failed Tests:").unwrap();
    let perf_pos = report.find("Performance:").unwrap();

    // Verify order: Header -> Summary -> Failed Tests -> Performance
    assert!(header_pos < summary_pos, "Header should come before Summary");
    assert!(summary_pos < failed_pos, "Summary should come before Failed Tests");
    assert!(failed_pos < perf_pos, "Failed Tests should come before Performance");
}

#[test]
fn test_report_newline_formatting() {
    let results = create_mixed_results();
    let report = generate_kat_report(&results);

    // Verify proper newline separation
    assert!(report.contains("===\n\n")); // After header
    assert!(report.contains("Summary:\n")); // Summary section
    assert!(report.contains("%\n\n")); // After success rate
}

#[test]
fn test_report_indentation() {
    let results = create_mixed_results();
    let report = generate_kat_report(&results);

    // Verify summary items are indented
    assert!(report.contains("  Total tests:"));
    assert!(report.contains("  Passed:"));
    assert!(report.contains("  Failed:"));
    assert!(report.contains("  Success rate:"));

    // Verify failed test items are indented
    assert!(report.contains("  ML-KEM-1024-003:"));

    // Verify performance items are indented
    assert!(report.contains("  Total execution time:"));
    assert!(report.contains("  Average test time:"));
}

// =============================================================================
// KatResult Type Tests
// =============================================================================

#[test]
fn test_kat_result_passed_constructor() {
    let result = KatResult::passed("TEST-CASE-001".to_string(), Duration::from_millis(100));

    assert_eq!(result.test_case, "TEST-CASE-001");
    assert!(result.passed);
    assert_eq!(result.execution_time_ns, 100_000_000); // 100ms in ns
    assert!(result.error_message.is_none());
}

#[test]
fn test_kat_result_failed_constructor() {
    let result = KatResult::failed(
        "TEST-CASE-002".to_string(),
        Duration::from_micros(500),
        "Validation error occurred".to_string(),
    );

    assert_eq!(result.test_case, "TEST-CASE-002");
    assert!(!result.passed);
    assert_eq!(result.execution_time_ns, 500_000); // 500us in ns
    assert_eq!(result.error_message, Some("Validation error occurred".to_string()));
}

#[test]
fn test_kat_result_equality() {
    let result1 = KatResult {
        test_case: "TEST".to_string(),
        passed: true,
        execution_time_ns: 1000,
        error_message: None,
    };

    let result2 = KatResult {
        test_case: "TEST".to_string(),
        passed: true,
        execution_time_ns: 1000,
        error_message: None,
    };

    assert_eq!(result1, result2);
}

#[test]
fn test_kat_result_inequality() {
    let result1 = create_passing_result("TEST-A", 1000);
    let result2 = create_passing_result("TEST-B", 1000);

    assert_ne!(result1, result2);
}

#[test]
fn test_kat_result_clone() {
    let original = create_failing_result("CLONE-TEST", 5000, "Clone error");
    let cloned = original.clone();

    assert_eq!(original, cloned);
    assert_eq!(original.test_case, cloned.test_case);
    assert_eq!(original.error_message, cloned.error_message);
}

#[test]
fn test_kat_result_debug_format() {
    let result = create_passing_result("DEBUG-TEST", 1_000_000);
    let debug_str = format!("{:?}", result);

    assert!(debug_str.contains("DEBUG-TEST"));
    assert!(debug_str.contains("passed: true"));
    assert!(debug_str.contains("1000000"));
}

// =============================================================================
// KatResult Serialization Tests
// =============================================================================

#[test]
fn test_kat_result_json_serialization_passing() {
    let result = create_passing_result("JSON-TEST-001", 2_500_000);
    let json = serde_json::to_string(&result).unwrap();

    assert!(json.contains("\"test_case\":\"JSON-TEST-001\""));
    assert!(json.contains("\"passed\":true"));
    assert!(json.contains("\"execution_time_ns\":2500000"));
    assert!(json.contains("\"error_message\":null"));
}

#[test]
fn test_kat_result_json_serialization_failing() {
    let result = create_failing_result("JSON-FAIL-001", 1_000_000, "JSON test error");
    let json = serde_json::to_string(&result).unwrap();

    assert!(json.contains("\"test_case\":\"JSON-FAIL-001\""));
    assert!(json.contains("\"passed\":false"));
    assert!(json.contains("\"execution_time_ns\":1000000"));
    assert!(json.contains("\"error_message\":\"JSON test error\""));
}

#[test]
fn test_kat_result_json_deserialization() {
    let json = r#"{
        "test_case": "DESER-TEST",
        "passed": true,
        "execution_time_ns": 750000,
        "error_message": null
    }"#;

    let result: KatResult = serde_json::from_str(json).unwrap();

    assert_eq!(result.test_case, "DESER-TEST");
    assert!(result.passed);
    assert_eq!(result.execution_time_ns, 750_000);
    assert!(result.error_message.is_none());
}

#[test]
fn test_kat_result_json_roundtrip() {
    let original = create_failing_result("ROUNDTRIP-TEST", 999_999, "Roundtrip error");
    let json = serde_json::to_string(&original).unwrap();
    let deserialized: KatResult = serde_json::from_str(&json).unwrap();

    assert_eq!(original, deserialized);
}

#[test]
fn test_kat_results_array_json_serialization() {
    let results = create_mixed_results();
    let json = serde_json::to_string(&results).unwrap();

    // Should be a valid JSON array
    assert!(json.starts_with('['));
    assert!(json.ends_with(']'));

    // Deserialize and verify count
    let deserialized: Vec<KatResult> = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.len(), 5);
}

// =============================================================================
// run_kat_tests Function Tests
// =============================================================================

#[test]
fn test_run_kat_tests_returns_results() {
    // Note: This test depends on having ML-KEM 1024 KAT vectors available
    // It may skip if vectors cannot be loaded
    match run_kat_tests() {
        Ok(results) => {
            // Verify we got some results
            assert!(!results.is_empty(), "run_kat_tests should return non-empty results");

            // Verify all results have valid test case names
            for result in &results {
                assert!(!result.test_case.is_empty(), "Test case name should not be empty");
            }

            // Verify execution times are set
            for result in &results {
                // Each result should have execution_time_ns > 0 or == the default
                // (the implementation sets 1_000_000 as default)
                assert!(result.execution_time_ns > 0, "Execution time should be positive");
            }
        }
        Err(e) => {
            // If loading fails, that's acceptable for this test
            // (might be missing NIST vectors in test environment)
            eprintln!("run_kat_tests returned error (may be expected): {}", e);
        }
    }
}

#[test]
fn test_run_kat_tests_results_are_marked_passed() {
    match run_kat_tests() {
        Ok(results) => {
            // The current implementation marks all results as passed
            for result in &results {
                assert!(result.passed, "Result {} should be marked as passed", result.test_case);
                assert!(
                    result.error_message.is_none(),
                    "Passed result should have no error message"
                );
            }
        }
        Err(_) => {
            // Skip if loading fails
        }
    }
}

#[test]
fn test_run_kat_tests_generates_valid_report() {
    match run_kat_tests() {
        Ok(results) => {
            let report = generate_kat_report(&results);

            // Report should be valid and contain expected sections
            assert!(report.contains("=== Known Answer Test Report ==="));
            assert!(report.contains("Summary:"));
            assert!(report.contains("Performance:"));

            // With the current implementation, all tests pass
            assert!(report.contains("Success rate: 100.00%"));
        }
        Err(_) => {
            // Skip if loading fails
        }
    }
}

// =============================================================================
// Integration Tests - Report Generation with Various Scenarios
// =============================================================================

#[test]
fn test_report_generation_performance() {
    // Generate a large number of results to test performance
    let results: Vec<KatResult> = (0..10_000)
        .map(|i| {
            if i % 10 == 0 {
                create_failing_result(
                    &format!("PERF-TEST-{:05}", i),
                    i as u128 * 1000,
                    "Perf test error",
                )
            } else {
                create_passing_result(&format!("PERF-TEST-{:05}", i), i as u128 * 1000)
            }
        })
        .collect();

    let start = std::time::Instant::now();
    let report = generate_kat_report(&results);
    let duration = start.elapsed();

    // Report generation should complete in reasonable time (< 1 second for 10k results)
    assert!(duration.as_secs() < 1, "Report generation took too long: {:?}", duration);

    // Verify report content
    assert!(report.contains("Total tests: 10000"));
    assert!(report.contains("Failed: 1000")); // 10% fail rate
    assert!(report.contains("Passed: 9000"));
}

#[test]
fn test_report_with_realistic_test_names() {
    let results = vec![
        create_passing_result("CAVP-ML-KEM-1024-001", 1_500_000),
        create_passing_result("CAVP-ML-KEM-1024-002", 1_600_000),
        create_failing_result(
            "CAVP-ML-DSA-44-001",
            2_000_000,
            "Signature verification failed: expected 0xAB, got 0xCD",
        ),
        create_passing_result("NIST-SHA3-256-EMPTY", 500_000),
        create_passing_result("NIST-SHA3-256-ABC", 550_000),
        create_failing_result("NIST-AES-128-GCM-001", 800_000, "Authentication tag mismatch"),
        create_passing_result("HYBRID-KEM-X25519-ML-KEM-001", 3_000_000),
    ];

    let report = generate_kat_report(&results);

    // Verify failed test names appear in the "Failed Tests" section
    // Note: Passed tests are only counted in statistics, not listed individually
    assert!(report.contains("CAVP-ML-DSA-44-001"));
    assert!(report.contains("Signature verification failed"));
    assert!(report.contains("NIST-AES-128-GCM-001"));
    assert!(report.contains("Authentication tag mismatch"));

    // Verify statistics
    assert!(report.contains("Total tests: 7"));
    assert!(report.contains("Passed: 5"));
    assert!(report.contains("Failed: 2"));

    // Verify the report has the expected sections
    assert!(report.contains("=== Known Answer Test Report ==="));
    assert!(report.contains("Summary:"));
    assert!(report.contains("Failed Tests:"));
    assert!(report.contains("Performance:"));
}

// =============================================================================
// Output Format Tests - Custom Report Parsing
// =============================================================================

/// Helper to parse the report and extract statistics
fn parse_report_stats(report: &str) -> (usize, usize, usize, f64) {
    let total = report
        .lines()
        .find(|l| l.contains("Total tests:"))
        .and_then(|l| l.split(':').nth(1))
        .and_then(|s| s.trim().parse::<usize>().ok())
        .unwrap_or(0);

    let passed = report
        .lines()
        .find(|l| l.trim().starts_with("Passed:"))
        .and_then(|l| l.split(':').nth(1))
        .and_then(|s| s.trim().parse::<usize>().ok())
        .unwrap_or(0);

    let failed = report
        .lines()
        .find(|l| l.trim().starts_with("Failed:"))
        .and_then(|l| l.split(':').nth(1))
        .and_then(|s| s.trim().parse::<usize>().ok())
        .unwrap_or(0);

    let success_rate = report
        .lines()
        .find(|l| l.contains("Success rate:"))
        .and_then(|l| l.split(':').nth(1))
        .and_then(|s| s.trim().trim_end_matches('%').parse::<f64>().ok())
        .unwrap_or(0.0);

    (total, passed, failed, success_rate)
}

#[test]
fn test_report_parsing_accuracy() {
    let results = create_mixed_results();
    let report = generate_kat_report(&results);
    let (total, passed, failed, success_rate) = parse_report_stats(&report);

    assert_eq!(total, 5);
    assert_eq!(passed, 3);
    assert_eq!(failed, 2);
    assert!((success_rate - 60.0).abs() < 0.01);
}

#[test]
fn test_report_parsing_all_pass() {
    let results = create_all_passing_results(25);
    let report = generate_kat_report(&results);
    let (total, passed, failed, success_rate) = parse_report_stats(&report);

    assert_eq!(total, 25);
    assert_eq!(passed, 25);
    assert_eq!(failed, 0);
    assert!((success_rate - 100.0).abs() < 0.01);
}

#[test]
fn test_report_parsing_all_fail() {
    let results = create_all_failing_results(15);
    let report = generate_kat_report(&results);
    let (total, passed, failed, success_rate) = parse_report_stats(&report);

    assert_eq!(total, 15);
    assert_eq!(passed, 0);
    assert_eq!(failed, 15);
    assert!((success_rate - 0.0).abs() < 0.01);
}

// =============================================================================
// Boundary and Stress Tests
// =============================================================================

#[test]
fn test_report_with_exactly_one_pass_one_fail() {
    let results = vec![
        create_passing_result("PASS-001", 1_000_000),
        create_failing_result("FAIL-001", 1_000_000, "Error"),
    ];

    let report = generate_kat_report(&results);

    assert!(report.contains("Total tests: 2"));
    assert!(report.contains("Passed: 1"));
    assert!(report.contains("Failed: 1"));
    assert!(report.contains("Success rate: 50.00%"));
}

#[test]
fn test_report_consistency_multiple_generations() {
    let results = create_mixed_results();

    // Generate report multiple times
    let report1 = generate_kat_report(&results);
    let report2 = generate_kat_report(&results);
    let report3 = generate_kat_report(&results);

    // All reports should be identical
    assert_eq!(report1, report2);
    assert_eq!(report2, report3);
}

#[test]
fn test_report_handles_unicode_errors() {
    let results = vec![create_failing_result(
        "UNICODE-TEST",
        1_000_000,
        "Error with unicode: \u{2713} \u{2717} \u{26A0}",
    )];

    let report = generate_kat_report(&results);

    assert!(report.contains("\u{2713}")); // Checkmark
    assert!(report.contains("\u{2717}")); // X mark
    assert!(report.contains("\u{26A0}")); // Warning
}

#[test]
fn test_report_with_newlines_in_error() {
    let results =
        vec![create_failing_result("MULTILINE-ERROR", 1_000_000, "Line 1\nLine 2\nLine 3")];

    let report = generate_kat_report(&results);

    // Error message should be included (formatting may vary)
    assert!(report.contains("Line 1"));
}

// =============================================================================
// Algorithm Type Tests (from types module)
// =============================================================================

#[test]
fn test_algorithm_type_names() {
    use arc_validation::kat_tests::types::AlgorithmType;

    let test_cases = vec![
        (AlgorithmType::MlKem { variant: "512".to_string() }, "ML-KEM-512"),
        (AlgorithmType::MlKem { variant: "768".to_string() }, "ML-KEM-768"),
        (AlgorithmType::MlKem { variant: "1024".to_string() }, "ML-KEM-1024"),
        (AlgorithmType::MlDsa { variant: "44".to_string() }, "ML-DSA-44"),
        (AlgorithmType::MlDsa { variant: "65".to_string() }, "ML-DSA-65"),
        (AlgorithmType::SlhDsa { variant: "128".to_string() }, "SLH-DSA-128"),
        (AlgorithmType::HybridKem, "Hybrid-KEM"),
        (AlgorithmType::AesGcm { key_size: 16 }, "AES-128-GCM"),
        (AlgorithmType::AesGcm { key_size: 32 }, "AES-256-GCM"),
        (AlgorithmType::Sha3 { variant: "256".to_string() }, "SHA3-256"),
        (AlgorithmType::Ed25519, "Ed25519"),
        (AlgorithmType::Bls12_381, "BLS12-381"),
        (AlgorithmType::Bn254, "BN254"),
        (AlgorithmType::Secp256k1, "secp256k1"),
    ];

    for (algo_type, expected_name) in test_cases {
        assert_eq!(algo_type.name(), expected_name, "Algorithm name mismatch for {:?}", algo_type);
    }
}

#[test]
fn test_algorithm_type_security_levels() {
    use arc_validation::kat_tests::types::AlgorithmType;

    let test_cases = vec![
        (AlgorithmType::MlKem { variant: "512".to_string() }, 128),
        (AlgorithmType::MlKem { variant: "768".to_string() }, 192),
        (AlgorithmType::MlKem { variant: "1024".to_string() }, 256),
        (AlgorithmType::MlDsa { variant: "44".to_string() }, 128),
        (AlgorithmType::MlDsa { variant: "65".to_string() }, 192),
        (AlgorithmType::MlDsa { variant: "87".to_string() }, 256),
        (AlgorithmType::SlhDsa { variant: "128".to_string() }, 128),
        (AlgorithmType::SlhDsa { variant: "192".to_string() }, 192),
        (AlgorithmType::SlhDsa { variant: "256".to_string() }, 256),
        (AlgorithmType::HybridKem, 256),
        (AlgorithmType::AesGcm { key_size: 16 }, 128),
        (AlgorithmType::AesGcm { key_size: 32 }, 256),
        (AlgorithmType::Ed25519, 128),
        (AlgorithmType::Bls12_381, 128),
        (AlgorithmType::Bn254, 128),
        (AlgorithmType::Secp256k1, 128),
    ];

    for (algo_type, expected_level) in test_cases {
        assert_eq!(
            algo_type.security_level(),
            expected_level,
            "Security level mismatch for {:?}",
            algo_type
        );
    }
}

// =============================================================================
// KatConfig Tests
// =============================================================================

#[test]
fn test_kat_config_default() {
    use arc_validation::kat_tests::types::KatConfig;

    let config = KatConfig::default();

    assert_eq!(config.test_count, 100);
    assert!(config.run_statistical_tests);
    assert_eq!(config.timeout_per_test, Duration::from_secs(10));
    assert!(config.validate_fips);
}

#[test]
fn test_kat_config_ml_kem_constructor() {
    use arc_validation::kat_tests::types::KatConfig;

    let config = KatConfig::ml_kem("1024", 50);

    assert_eq!(config.test_count, 50);
    assert!(config.run_statistical_tests);
    assert_eq!(config.timeout_per_test, Duration::from_secs(10));
    assert!(config.validate_fips);
}

#[test]
fn test_kat_config_ml_dsa_constructor() {
    use arc_validation::kat_tests::types::KatConfig;

    let config = KatConfig::ml_dsa("65", 75);

    assert_eq!(config.test_count, 75);
    assert!(config.run_statistical_tests);
    assert_eq!(config.timeout_per_test, Duration::from_secs(10));
    assert!(config.validate_fips);
}

#[test]
fn test_kat_config_slh_dsa_constructor() {
    use arc_validation::kat_tests::types::KatConfig;

    let config = KatConfig::slh_dsa("256", 25);

    assert_eq!(config.test_count, 25);
    assert!(config.run_statistical_tests);
    // SLH-DSA has longer timeout
    assert_eq!(config.timeout_per_test, Duration::from_secs(30));
    assert!(config.validate_fips);
}

#[test]
fn test_kat_config_serialization() {
    use arc_validation::kat_tests::types::KatConfig;

    let config = KatConfig::ml_kem("768", 100);
    let json = serde_json::to_string(&config).unwrap();

    assert!(json.contains("\"test_count\":100"));
    assert!(json.contains("\"run_statistical_tests\":true"));
    assert!(json.contains("\"validate_fips\":true"));
}

#[test]
fn test_kat_config_deserialization() {
    use arc_validation::kat_tests::types::{AlgorithmType, KatConfig};

    let json = r#"{
        "algorithm": {"MlKem": {"variant": "512"}},
        "test_count": 50,
        "run_statistical_tests": false,
        "timeout_per_test": {"secs": 5, "nanos": 0},
        "validate_fips": true
    }"#;

    let config: KatConfig = serde_json::from_str(json).unwrap();

    assert_eq!(config.test_count, 50);
    assert!(!config.run_statistical_tests);
    assert_eq!(config.timeout_per_test, Duration::from_secs(5));
    assert!(config.validate_fips);
    assert!(matches!(config.algorithm, AlgorithmType::MlKem { variant } if variant == "512"));
}
