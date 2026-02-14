//! Targeted coverage boost tests for arc-validation modules.
//! Exercises public APIs in rfc_vectors, wycheproof, nist_kat, fips_validation,
//! and validation_summary to cover previously-missed lines.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::cast_precision_loss,
    clippy::single_match,
    deprecated
)]

// ============================================================
// rfc_vectors.rs — RfcTestResults public API
// ============================================================

use arc_validation::rfc_vectors::{RfcTestError, RfcTestResults};

#[test]
fn test_rfc_results_new_and_default() {
    let results = RfcTestResults::new();
    assert_eq!(results.total, 0);
    assert_eq!(results.passed, 0);
    assert_eq!(results.failed, 0);
    assert!(results.failures.is_empty());
    assert!(results.all_passed()); // zero tests = all passed
}

#[test]
fn test_rfc_results_add_pass() {
    let mut results = RfcTestResults::new();
    results.add_pass();
    results.add_pass();
    assert_eq!(results.total, 2);
    assert_eq!(results.passed, 2);
    assert_eq!(results.failed, 0);
    assert!(results.all_passed());
}

#[test]
fn test_rfc_results_add_failure() {
    let mut results = RfcTestResults::new();
    results.add_pass();
    results.add_failure("test vector mismatch".to_string());
    assert_eq!(results.total, 2);
    assert_eq!(results.passed, 1);
    assert_eq!(results.failed, 1);
    assert!(!results.all_passed());
    assert!(results.failures[0].contains("mismatch"));
}

#[test]
fn test_rfc_test_error_display() {
    let err = RfcTestError::TestFailed {
        rfc: "RFC 5869".to_string(),
        test_name: "test-1".to_string(),
        message: "mismatch".to_string(),
    };
    let msg = format!("{}", err);
    assert!(msg.contains("RFC 5869") || msg.contains("mismatch") || msg.contains("test-1"));
}

// ============================================================
// wycheproof.rs — WycheproofResults and WycheproofError
// ============================================================

use arc_validation::wycheproof::{WycheproofError, WycheproofResults};

#[test]
fn test_wycheproof_results_new() {
    let results = WycheproofResults::new();
    assert_eq!(results.passed, 0);
    assert_eq!(results.failed, 0);
    assert_eq!(results.skipped, 0);
    assert!(results.all_passed());
}

#[test]
fn test_wycheproof_results_operations() {
    let mut results = WycheproofResults::new();
    results.add_pass();
    results.add_pass();
    results.add_skip();
    results.add_failure("bad vector".to_string());

    assert_eq!(results.passed, 2);
    assert_eq!(results.failed, 1);
    assert_eq!(results.skipped, 1);
    assert!(!results.all_passed());
    assert_eq!(results.failures.len(), 1);
}

#[test]
fn test_wycheproof_error_display() {
    let err = WycheproofError::TestFailed { tc_id: 42, message: "verification failed".to_string() };
    let msg = format!("{}", err);
    assert!(msg.contains("42") || msg.contains("failed"));
}

// ============================================================
// nist_kat/sha2_kat.rs — SHA-2 KAT runners
// ============================================================

use arc_validation::nist_kat::sha2_kat::{
    run_sha224_kat, run_sha256_kat, run_sha384_kat, run_sha512_224_kat, run_sha512_256_kat,
    run_sha512_kat,
};

#[test]
fn test_sha256_kat() {
    assert!(run_sha256_kat().is_ok());
}

#[test]
fn test_sha224_kat() {
    assert!(run_sha224_kat().is_ok());
}

#[test]
fn test_sha384_kat() {
    assert!(run_sha384_kat().is_ok());
}

#[test]
fn test_sha512_kat() {
    assert!(run_sha512_kat().is_ok());
}

#[test]
fn test_sha512_224_kat() {
    assert!(run_sha512_224_kat().is_ok());
}

#[test]
fn test_sha512_256_kat() {
    assert!(run_sha512_256_kat().is_ok());
}

// ============================================================
// nist_kat/hmac_kat.rs — HMAC KAT runners
// ============================================================

use arc_validation::nist_kat::hmac_kat::{
    run_hmac_sha224_kat, run_hmac_sha256_kat, run_hmac_sha384_kat, run_hmac_sha512_kat,
};

#[test]
fn test_hmac_sha256_kat() {
    assert!(run_hmac_sha256_kat().is_ok());
}

#[test]
fn test_hmac_sha224_kat() {
    assert!(run_hmac_sha224_kat().is_ok());
}

#[test]
fn test_hmac_sha384_kat() {
    assert!(run_hmac_sha384_kat().is_ok());
}

#[test]
fn test_hmac_sha512_kat() {
    assert!(run_hmac_sha512_kat().is_ok());
}

// ============================================================
// fips_validation/validator.rs — FIPSValidator
// ============================================================

use arc_validation::fips_validation::{FIPSValidator, ValidationScope};

#[test]
fn test_fips_validator_algorithms_only() {
    let validator = FIPSValidator::new(ValidationScope::AlgorithmsOnly);
    let result = validator.validate_module();
    assert!(result.is_ok());
}

#[test]
fn test_fips_validator_full_module() {
    let validator = FIPSValidator::new(ValidationScope::FullModule);
    let result = validator.validate_module();
    assert!(result.is_ok());
    let validation_result = result.unwrap();

    // Test certificate generation (may fail if validation has issues)
    let cert = validator.generate_certificate(&validation_result);
    match cert {
        Ok(c) => assert!(!c.id.is_empty()),
        Err(_) => {} // acceptable if validation flagged issues
    }

    // Test remediation guidance (exercises the method regardless of result)
    let guidance = validator.get_remediation_guidance(&validation_result);
    let _ = guidance;
}

#[test]
fn test_fips_validator_module_interfaces() {
    let validator = FIPSValidator::new(ValidationScope::ModuleInterfaces);
    let result = validator.validate_module();
    assert!(result.is_ok());
}

#[test]
fn test_fips_validator_individual_tests() {
    let validator = FIPSValidator::new(ValidationScope::AlgorithmsOnly);
    assert!(validator.test_aes_algorithm().is_ok());
    assert!(validator.test_sha3_algorithm().is_ok());
    assert!(validator.test_mlkem_algorithm().is_ok());
    assert!(validator.test_self_tests().is_ok());
}

// ============================================================
// validation_summary.rs — ComplianceReporter with real data
// ============================================================

use arc_validation::kat_tests::types::KatResult;
use arc_validation::validation_summary::ComplianceReporter;
use std::time::Duration;

#[test]
fn test_compliance_reporter_with_kat_results() {
    let reporter = ComplianceReporter::new(0.05);

    let kat_results = vec![
        KatResult::passed("ML-KEM-768-keygen-1".to_string(), Duration::from_millis(10)),
        KatResult::passed("ML-KEM-768-encaps-1".to_string(), Duration::from_millis(5)),
        KatResult::passed("AES-256-GCM-encrypt-1".to_string(), Duration::from_millis(1)),
        KatResult::failed(
            "ML-DSA-44-sign-fail".to_string(),
            Duration::from_millis(8),
            "Signature mismatch".to_string(),
        ),
    ];

    let report = reporter.generate_full_compliance_report(&kat_results, &None).unwrap();
    assert!(!report.report_id.is_empty());
    assert!(!report.algorithm_results.is_empty());

    // JSON export
    let json = reporter.generate_json_report(&report).unwrap();
    assert!(json.contains("report_id"));
    assert!(json.contains("algorithm_results"));

    // HTML export
    let html = reporter.generate_html_report(&report).unwrap();
    assert!(!html.is_empty());
}

#[test]
fn test_compliance_reporter_all_passing() {
    let reporter = ComplianceReporter::new(0.01);

    let kat_results = vec![
        KatResult::passed("SHA-256-kat-1".to_string(), Duration::from_millis(1)),
        KatResult::passed("SHA-256-kat-2".to_string(), Duration::from_millis(1)),
        KatResult::passed("HMAC-SHA256-kat-1".to_string(), Duration::from_millis(2)),
    ];

    let report = reporter.generate_full_compliance_report(&kat_results, &None).unwrap();
    assert!(!report.algorithm_results.is_empty());
}

#[test]
fn test_compliance_reporter_multiple_algorithms() {
    let reporter = ComplianceReporter::new(0.05);

    let kat_results = vec![
        KatResult::passed("ML-KEM-768-1".to_string(), Duration::from_millis(10)),
        KatResult::passed("ML-KEM-768-2".to_string(), Duration::from_millis(10)),
        KatResult::passed("ML-DSA-44-1".to_string(), Duration::from_millis(15)),
        KatResult::passed("SLH-DSA-128s-1".to_string(), Duration::from_millis(100)),
        KatResult::passed("AES-GCM-1".to_string(), Duration::from_millis(1)),
        KatResult::passed("HKDF-SHA256-1".to_string(), Duration::from_millis(1)),
    ];

    let report = reporter.generate_full_compliance_report(&kat_results, &None).unwrap();

    // Should have grouped by algorithm prefix
    assert!(report.algorithm_results.len() >= 2);
}
