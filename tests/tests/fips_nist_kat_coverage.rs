#![deny(unsafe_code)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::panic)]
#![allow(clippy::indexing_slicing)]
#![allow(clippy::float_cmp)]
#![allow(missing_docs)]

//! Coverage tests for nist_kat/mod.rs
//!
//! Tests decode_hex, KatTestResult, NistKatError Display variants.

use latticearc_tests::validation::nist_kat::{KatTestResult, NistKatError, decode_hex};

// ============================================================================
// decode_hex
// ============================================================================

#[test]
fn test_decode_hex_valid() {
    let bytes = decode_hex("48656c6c6f").unwrap();
    assert_eq!(bytes, b"Hello");
}

#[test]
fn test_decode_hex_empty() {
    let bytes = decode_hex("").unwrap();
    assert!(bytes.is_empty());
}

#[test]
fn test_decode_hex_uppercase() {
    let bytes = decode_hex("DEADBEEF").unwrap();
    assert_eq!(bytes, vec![0xDE, 0xAD, 0xBE, 0xEF]);
}

#[test]
fn test_decode_hex_invalid_chars() {
    let result = decode_hex("ZZZZ");
    assert!(result.is_err());
    match result.unwrap_err() {
        NistKatError::HexError(msg) => {
            assert!(!msg.is_empty());
        }
        other => panic!("Expected HexError, got {:?}", other),
    }
}

#[test]
fn test_decode_hex_odd_length() {
    let result = decode_hex("ABC");
    assert!(result.is_err());
}

// ============================================================================
// KatTestResult constructors
// ============================================================================

#[test]
fn test_kat_test_result_passed() {
    let result = KatTestResult::passed("TC1".to_string(), "AES-GCM".to_string(), 42);
    assert!(result.passed);
    assert_eq!(result.test_case, "TC1");
    assert_eq!(result.algorithm, "AES-GCM");
    assert_eq!(result.execution_time_us, 42);
    assert!(result.error_message.is_none());
}

#[test]
fn test_kat_test_result_failed() {
    let result = KatTestResult::failed(
        "TC2".to_string(),
        "SHA-256".to_string(),
        "hash mismatch".to_string(),
        100,
    );
    assert!(!result.passed);
    assert_eq!(result.test_case, "TC2");
    assert_eq!(result.algorithm, "SHA-256");
    assert_eq!(result.execution_time_us, 100);
    assert_eq!(result.error_message.as_deref(), Some("hash mismatch"));
}

#[test]
fn test_kat_test_result_clone() {
    let result = KatTestResult::passed("TC1".to_string(), "AES".to_string(), 10);
    let cloned = result.clone();
    assert_eq!(cloned.test_case, result.test_case);
    assert_eq!(cloned.passed, result.passed);
}

#[test]
fn test_kat_test_result_debug() {
    let result = KatTestResult::failed("TC3".to_string(), "HKDF".to_string(), "bad".to_string(), 5);
    let debug = format!("{:?}", result);
    assert!(debug.contains("KatTestResult"));
}

// ============================================================================
// NistKatError Display
// ============================================================================

#[test]
fn test_nist_kat_error_test_failed_display() {
    let err = NistKatError::TestFailed {
        algorithm: "AES-GCM".to_string(),
        test_name: "TC1".to_string(),
        message: "tag mismatch".to_string(),
    };
    let display = format!("{}", err);
    assert!(display.contains("AES-GCM"));
    assert!(display.contains("TC1"));
    assert!(display.contains("tag mismatch"));
}

#[test]
fn test_nist_kat_error_hex_error_display() {
    let err = NistKatError::HexError("invalid hex".to_string());
    let display = format!("{}", err);
    assert!(display.contains("Hex decode error"));
    assert!(display.contains("invalid hex"));
}

#[test]
fn test_nist_kat_error_implementation_error_display() {
    let err = NistKatError::ImplementationError("algo not found".to_string());
    let display = format!("{}", err);
    assert!(display.contains("Implementation error"));
    assert!(display.contains("algo not found"));
}

#[test]
fn test_nist_kat_error_unsupported_algorithm_display() {
    let err = NistKatError::UnsupportedAlgorithm("SIKE".to_string());
    let display = format!("{}", err);
    assert!(display.contains("Unsupported algorithm"));
    assert!(display.contains("SIKE"));
}

#[test]
fn test_nist_kat_error_debug() {
    let err = NistKatError::HexError("test".to_string());
    let debug = format!("{:?}", err);
    assert!(debug.contains("HexError"));
}

// ============================================================================
// KatSummary
// ============================================================================

use latticearc_tests::validation::nist_kat::runner::{KatRunner, KatSummary};

#[test]
fn test_kat_summary_new_is_empty() {
    let summary = KatSummary::new();
    assert_eq!(summary.total, 0);
    assert_eq!(summary.passed, 0);
    assert_eq!(summary.failed, 0);
    assert!(summary.results.is_empty());
    assert_eq!(summary.total_time_ms, 0);
}

#[test]
fn test_kat_summary_default_equals_new() {
    let summary = KatSummary::default();
    assert_eq!(summary.total, 0);
    assert_eq!(summary.passed, 0);
}

#[test]
fn test_kat_summary_add_passed_result() {
    let mut summary = KatSummary::new();
    summary.add_result(KatTestResult::passed("TC1".to_string(), "AES".to_string(), 2000));
    assert_eq!(summary.total, 1);
    assert_eq!(summary.passed, 1);
    assert_eq!(summary.failed, 0);
    assert_eq!(summary.total_time_ms, 2);
    assert!(summary.all_passed());
}

#[test]
fn test_kat_summary_add_failed_result() {
    let mut summary = KatSummary::new();
    summary.add_result(KatTestResult::failed(
        "TC2".to_string(),
        "HMAC".to_string(),
        "wrong".to_string(),
        5000,
    ));
    assert_eq!(summary.total, 1);
    assert_eq!(summary.passed, 0);
    assert_eq!(summary.failed, 1);
    assert!(!summary.all_passed());
}

#[test]
fn test_kat_summary_mixed_results() {
    let mut summary = KatSummary::new();
    summary.add_result(KatTestResult::passed("T1".to_string(), "A".to_string(), 1000));
    summary.add_result(KatTestResult::passed("T2".to_string(), "A".to_string(), 2000));
    summary.add_result(KatTestResult::failed(
        "T3".to_string(),
        "B".to_string(),
        "fail".to_string(),
        3000,
    ));
    assert_eq!(summary.total, 3);
    assert_eq!(summary.passed, 2);
    assert_eq!(summary.failed, 1);
    assert!(!summary.all_passed());
}

#[test]
fn test_kat_summary_pass_rate_all_passed() {
    let mut summary = KatSummary::new();
    summary.add_result(KatTestResult::passed("T1".to_string(), "A".to_string(), 0));
    summary.add_result(KatTestResult::passed("T2".to_string(), "A".to_string(), 0));
    assert_eq!(summary.pass_rate(), 100.0);
}

#[test]
fn test_kat_summary_pass_rate_none_passed() {
    let mut summary = KatSummary::new();
    summary.add_result(KatTestResult::failed(
        "T1".to_string(),
        "A".to_string(),
        "f".to_string(),
        0,
    ));
    assert_eq!(summary.pass_rate(), 0.0);
}

#[test]
fn test_kat_summary_pass_rate_empty() {
    let summary = KatSummary::new();
    assert_eq!(summary.pass_rate(), 0.0);
}

#[test]
fn test_kat_summary_pass_rate_half() {
    let mut summary = KatSummary::new();
    summary.add_result(KatTestResult::passed("T1".to_string(), "A".to_string(), 0));
    summary.add_result(KatTestResult::failed(
        "T2".to_string(),
        "A".to_string(),
        "f".to_string(),
        0,
    ));
    assert_eq!(summary.pass_rate(), 50.0);
}

#[test]
fn test_kat_summary_print_all_passed() {
    let mut summary = KatSummary::new();
    summary.add_result(KatTestResult::passed("TC1".to_string(), "AES-GCM".to_string(), 1000));
    summary.add_result(KatTestResult::passed("TC2".to_string(), "SHA-256".to_string(), 2000));
    summary.print();
}

#[test]
fn test_kat_summary_print_with_failures() {
    let mut summary = KatSummary::new();
    summary.add_result(KatTestResult::passed("TC1".to_string(), "AES-GCM".to_string(), 100));
    summary.add_result(KatTestResult::failed(
        "TC2".to_string(),
        "ML-KEM".to_string(),
        "encap mismatch".to_string(),
        200,
    ));
    summary.add_result(KatTestResult::failed(
        "TC3".to_string(),
        "HMAC".to_string(),
        "tag mismatch".to_string(),
        300,
    ));
    summary.print();
}

#[test]
fn test_kat_summary_print_empty() {
    let summary = KatSummary::new();
    summary.print();
}

#[test]
fn test_kat_summary_print_multiple_algorithms() {
    let mut summary = KatSummary::new();
    for i in 0..5 {
        summary.add_result(KatTestResult::passed(format!("TC{}", i), "AES-GCM".to_string(), 100));
    }
    for i in 5..8 {
        summary.add_result(KatTestResult::passed(format!("TC{}", i), "SHA-256".to_string(), 200));
    }
    summary.add_result(KatTestResult::passed("TC8".to_string(), "HKDF".to_string(), 50));
    summary.print();
}

#[test]
fn test_kat_summary_print_failed_no_error_message() {
    let mut summary = KatSummary::new();
    summary.add_result(KatTestResult {
        test_case: "TC_NO_MSG".to_string(),
        algorithm: "TestAlgo".to_string(),
        passed: false,
        error_message: None,
        execution_time_us: 0,
    });
    summary.print();
    assert_eq!(summary.failed, 1);
}

#[test]
fn test_kat_summary_clone_and_debug() {
    let mut summary = KatSummary::new();
    summary.add_result(KatTestResult::passed("T1".to_string(), "A".to_string(), 0));
    let cloned = summary.clone();
    assert_eq!(cloned.total, 1);
    let debug = format!("{:?}", summary);
    assert!(debug.contains("KatSummary"));
}

#[test]
fn test_kat_summary_accumulated_time() {
    let mut summary = KatSummary::new();
    summary.add_result(KatTestResult::passed("T1".to_string(), "A".to_string(), 5000));
    summary.add_result(KatTestResult::passed("T2".to_string(), "A".to_string(), 3000));
    summary.add_result(KatTestResult::failed(
        "T3".to_string(),
        "B".to_string(),
        "err".to_string(),
        2000,
    ));
    assert_eq!(summary.total_time_ms, 10);
}

// ============================================================================
// KatRunner
// ============================================================================

#[test]
fn test_kat_runner_new() {
    let runner = KatRunner::new();
    assert_eq!(runner.summary().total, 0);
    assert!(runner.summary().all_passed());
}

#[test]
fn test_kat_runner_default() {
    let runner = KatRunner::default();
    assert_eq!(runner.summary().total, 0);
}

#[test]
fn test_kat_runner_run_passing_test() {
    let mut runner = KatRunner::new();
    runner.run_test("TC1", "TestAlgo", || Ok(()));
    assert_eq!(runner.summary().total, 1);
    assert_eq!(runner.summary().passed, 1);
    assert!(runner.summary().all_passed());
}

#[test]
fn test_kat_runner_run_failing_test() {
    let mut runner = KatRunner::new();
    runner.run_test("TC1", "TestAlgo", || {
        Err(NistKatError::TestFailed {
            algorithm: "TestAlgo".to_string(),
            test_name: "TC1".to_string(),
            message: "mismatch".to_string(),
        })
    });
    assert_eq!(runner.summary().failed, 1);
    assert!(!runner.summary().all_passed());
}

#[test]
fn test_kat_runner_run_multiple_tests() {
    let mut runner = KatRunner::new();
    runner.run_test("TC1", "A", || Ok(()));
    runner.run_test("TC2", "A", || Ok(()));
    runner.run_test("TC3", "B", || Err(NistKatError::ImplementationError("bug".to_string())));
    runner.run_test("TC4", "B", || Ok(()));
    assert_eq!(runner.summary().total, 4);
    assert_eq!(runner.summary().passed, 3);
    assert_eq!(runner.summary().failed, 1);
}

#[test]
fn test_kat_runner_finish_consumes() {
    let mut runner = KatRunner::new();
    runner.run_test("TC1", "Algo", || Ok(()));
    runner.run_test("TC2", "Algo", || Err(NistKatError::HexError("bad".to_string())));
    let summary = runner.finish();
    assert_eq!(summary.total, 2);
    assert_eq!(summary.passed, 1);
    assert_eq!(summary.failed, 1);
}

#[test]
fn test_kat_runner_error_message_preserved() {
    let mut runner = KatRunner::new();
    runner.run_test("TC1", "ML-KEM", || {
        Err(NistKatError::TestFailed {
            algorithm: "ML-KEM".to_string(),
            test_name: "TC1".to_string(),
            message: "shared secret mismatch".to_string(),
        })
    });
    let summary = runner.finish();
    let result = &summary.results[0];
    assert!(!result.passed);
    assert!(result.error_message.as_ref().unwrap().contains("shared secret mismatch"));
}

#[test]
fn test_kat_runner_unsupported_algorithm_error() {
    let mut runner = KatRunner::new();
    runner.run_test("TC1", "SIKE", || Err(NistKatError::UnsupportedAlgorithm("SIKE".to_string())));
    let summary = runner.finish();
    assert_eq!(summary.failed, 1);
    assert!(summary.results[0].error_message.as_ref().unwrap().contains("SIKE"));
}
