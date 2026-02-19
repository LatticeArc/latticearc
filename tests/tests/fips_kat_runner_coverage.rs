#![deny(unsafe_code)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::panic)]
#![allow(clippy::indexing_slicing)]
#![allow(clippy::arithmetic_side_effects)]
#![allow(missing_docs)]

//! Coverage tests for `KatRunner` and `KatSummary` in nist_kat/runner.rs.

use latticearc_tests::validation::nist_kat::runner::{KatRunner, KatSummary};
use latticearc_tests::validation::nist_kat::{KatTestResult, NistKatError};

// ============================================================================
// KatSummary
// ============================================================================

#[test]
fn test_kat_summary_new() {
    let summary = KatSummary::new();
    assert_eq!(summary.total, 0);
    assert_eq!(summary.passed, 0);
    assert_eq!(summary.failed, 0);
    assert!(summary.results.is_empty());
    assert_eq!(summary.total_time_ms, 0);
}

#[test]
fn test_kat_summary_default() {
    let summary = KatSummary::default();
    assert_eq!(summary.total, 0);
    assert!(summary.all_passed()); // No failures = all passed
}

#[test]
fn test_kat_summary_add_passed_result() {
    let mut summary = KatSummary::new();
    let result = KatTestResult::passed("test1".to_string(), "AES-GCM".to_string(), 5000);
    summary.add_result(result);

    assert_eq!(summary.total, 1);
    assert_eq!(summary.passed, 1);
    assert_eq!(summary.failed, 0);
    assert!(summary.all_passed());
    assert!((summary.pass_rate() - 100.0).abs() < 0.01);
}

#[test]
fn test_kat_summary_add_failed_result() {
    let mut summary = KatSummary::new();
    let result = KatTestResult::failed(
        "test1".to_string(),
        "SHA3".to_string(),
        "mismatch".to_string(),
        3000,
    );
    summary.add_result(result);

    assert_eq!(summary.total, 1);
    assert_eq!(summary.passed, 0);
    assert_eq!(summary.failed, 1);
    assert!(!summary.all_passed());
    assert!((summary.pass_rate() - 0.0).abs() < 0.01);
}

#[test]
fn test_kat_summary_mixed_results() {
    let mut summary = KatSummary::new();
    summary.add_result(KatTestResult::passed("t1".to_string(), "AES".to_string(), 1000));
    summary.add_result(KatTestResult::passed("t2".to_string(), "AES".to_string(), 2000));
    summary.add_result(KatTestResult::failed(
        "t3".to_string(),
        "SHA3".to_string(),
        "err".to_string(),
        3000,
    ));

    assert_eq!(summary.total, 3);
    assert_eq!(summary.passed, 2);
    assert_eq!(summary.failed, 1);
    assert!(!summary.all_passed());
    assert!((summary.pass_rate() - 66.666).abs() < 1.0);
}

#[test]
fn test_kat_summary_pass_rate_empty() {
    let summary = KatSummary::new();
    assert!((summary.pass_rate() - 0.0).abs() < 0.01);
}

#[test]
fn test_kat_summary_print_empty() {
    let summary = KatSummary::new();
    summary.print(); // Should not panic
}

#[test]
fn test_kat_summary_print_with_results() {
    let mut summary = KatSummary::new();
    summary.add_result(KatTestResult::passed("enc-1".to_string(), "AES-GCM".to_string(), 1500));
    summary.add_result(KatTestResult::passed("enc-2".to_string(), "AES-GCM".to_string(), 2500));
    summary.add_result(KatTestResult::passed("hash-1".to_string(), "SHA3-256".to_string(), 800));
    summary.print(); // Should print per-algorithm breakdown
}

#[test]
fn test_kat_summary_print_with_failures() {
    let mut summary = KatSummary::new();
    summary.add_result(KatTestResult::passed("enc-1".to_string(), "AES-GCM".to_string(), 1000));
    summary.add_result(KatTestResult::failed(
        "enc-2".to_string(),
        "AES-GCM".to_string(),
        "Authentication tag mismatch".to_string(),
        2000,
    ));
    summary.print(); // Should print failed tests section
}

// ============================================================================
// KatRunner
// ============================================================================

#[test]
fn test_kat_runner_new() {
    let runner = KatRunner::new();
    assert_eq!(runner.summary().total, 0);
}

#[test]
fn test_kat_runner_default() {
    let runner = KatRunner::default();
    assert_eq!(runner.summary().total, 0);
}

#[test]
fn test_kat_runner_run_passing_test() {
    let mut runner = KatRunner::new();
    runner.run_test("aes-gcm-256-encrypt", "AES-GCM", || Ok(()));

    let summary = runner.summary();
    assert_eq!(summary.total, 1);
    assert_eq!(summary.passed, 1);
    assert!(summary.all_passed());
}

#[test]
fn test_kat_runner_run_failing_test() {
    let mut runner = KatRunner::new();
    runner.run_test("sha3-256-hash", "SHA3-256", || {
        Err(NistKatError::TestFailed {
            algorithm: "SHA3-256".to_string(),
            test_name: "sha3-256-hash".to_string(),
            message: "hash mismatch".to_string(),
        })
    });

    let summary = runner.summary();
    assert_eq!(summary.total, 1);
    assert_eq!(summary.failed, 1);
    assert!(!summary.all_passed());
}

#[test]
fn test_kat_runner_multiple_tests() {
    let mut runner = KatRunner::new();
    runner.run_test("aes-1", "AES-GCM", || Ok(()));
    runner.run_test("aes-2", "AES-GCM", || Ok(()));
    runner.run_test("sha-1", "SHA3-256", || {
        Err(NistKatError::TestFailed {
            algorithm: "SHA3-256".to_string(),
            test_name: "sha-1".to_string(),
            message: "bad".to_string(),
        })
    });
    runner.run_test("ed25519-1", "Ed25519", || Ok(()));

    let summary = runner.summary();
    assert_eq!(summary.total, 4);
    assert_eq!(summary.passed, 3);
    assert_eq!(summary.failed, 1);
}

#[test]
fn test_kat_runner_finish() {
    let mut runner = KatRunner::new();
    runner.run_test("test-1", "AES", || Ok(()));
    runner.run_test("test-2", "AES", || Ok(()));

    let summary = runner.finish();
    assert_eq!(summary.total, 2);
    assert!(summary.all_passed());
    // runner is consumed, summary is owned
    assert_eq!(summary.results.len(), 2);
}

#[test]
fn test_kat_runner_run_test_records_timing() {
    let mut runner = KatRunner::new();
    runner.run_test("timing-test", "AES", || {
        // Do some minimal work
        let _x = [0u8; 100];
        Ok(())
    });

    let summary = runner.summary();
    assert_eq!(summary.results.len(), 1);
    // execution_time_us should be populated (may be 0 on fast systems)
    let _ = summary.results[0].execution_time_us;
}
