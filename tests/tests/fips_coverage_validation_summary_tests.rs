//! Coverage tests for validation_summary.rs
//!
//! Targets uncovered paths in ComplianceReporter, ComplianceReport generation,
//! HTML/JSON report generation, and recommendation generation.

#![allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::float_cmp,
    clippy::redundant_clone,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_lossless,
    clippy::cast_precision_loss,
    clippy::print_stdout,
    clippy::useless_format,
    clippy::needless_borrows_for_generic_args
)]

use chrono::Utc;
use latticearc_tests::validation::fips_validation_impl::Fips140_3ValidationResult;
use latticearc_tests::validation::kat_tests::types::KatResult;
use latticearc_tests::validation::validation_summary::{
    ComplianceMetrics, ComplianceReporter, ComplianceStatus, RandomnessQuality, SecurityCoverage,
    StatisticalComplianceResult, ValidationScope,
};
use std::time::Duration;

// Helper to create a passing KatResult
fn passing_kat(test_case: &str) -> KatResult {
    KatResult {
        test_case: test_case.to_string(),
        passed: true,
        execution_time_ns: 1000,
        error_message: None,
    }
}

// Helper to create a failing KatResult
fn failing_kat(test_case: &str, error: &str) -> KatResult {
    KatResult {
        test_case: test_case.to_string(),
        passed: false,
        execution_time_ns: 1000,
        error_message: Some(error.to_string()),
    }
}

// ============================================================================
// ComplianceReporter: generate_full_compliance_report
// ============================================================================

#[test]
fn test_compliance_reporter_new() {
    let reporter = ComplianceReporter::new(0.05);
    let _ = reporter;
}

#[test]
fn test_compliance_reporter_default() {
    let reporter = ComplianceReporter::default();
    let _ = reporter;
}

#[test]
fn test_generate_full_compliance_report_with_ml_kem_results() {
    let reporter = ComplianceReporter::new(0.01);

    let kat_results =
        vec![passing_kat("ML-KEM-768 KeyGen Test 1"), passing_kat("ML-KEM-768 KeyGen Test 2")];

    let report = reporter.generate_full_compliance_report(&kat_results, &None).unwrap();
    assert!(!report.report_id.is_empty());
    assert!(report.algorithm_results.contains_key("ML-KEM"));
    assert!(report.statistical_results.is_some());
    assert!(!report.recommendations.is_empty());
}

#[test]
fn test_generate_full_compliance_report_with_mixed_algorithms() {
    let reporter = ComplianceReporter::new(0.01);

    let kat_results = vec![
        passing_kat("ML-DSA-44 Sign Test"),
        passing_kat("AES-GCM Encrypt Test"),
        passing_kat("SLH-DSA-128s Sign Test"),
        passing_kat("Ed25519 Sign Test"),
        passing_kat("SHA3-256 Hash Test"),
        passing_kat("HYBRID KEM Test"),
        passing_kat("Unknown Algorithm Test"),
    ];

    let report = reporter.generate_full_compliance_report(&kat_results, &None).unwrap();
    assert!(report.algorithm_results.len() >= 5);
    assert!(report.security_level > 0);
}

#[test]
fn test_generate_full_compliance_report_with_failures() {
    let reporter = ComplianceReporter::new(0.01);

    let kat_results = vec![
        failing_kat("ML-KEM-768 Test 1", "Mismatch"),
        failing_kat("ML-KEM-768 Test 2", "Mismatch"),
    ];

    let report = reporter.generate_full_compliance_report(&kat_results, &None).unwrap();
    assert_eq!(report.overall_compliance, ComplianceStatus::NonCompliant);
    assert!(report.recommendations.iter().any(|r| r.contains("Critical") || r.contains("action")));
}

#[test]
fn test_generate_full_compliance_report_with_fips_validation() {
    let reporter = ComplianceReporter::new(0.01);

    let kat_results = vec![passing_kat("ML-KEM-768 Test")];

    let fips_result = Fips140_3ValidationResult {
        validation_id: "test-123".to_string(),
        timestamp: Utc::now(),
        power_up_tests: vec![],
        conditional_tests: vec![],
        overall_passed: true,
        compliance_level: "FIPS 140-3 Level 3".to_string(),
        module_name: "TestModule".to_string(),
        execution_time: Duration::from_millis(100),
        detailed_results: serde_json::json!({}),
    };

    let report =
        reporter.generate_full_compliance_report(&kat_results, &Some(fips_result)).unwrap();
    assert!(report.fips_validation.is_some());
}

// ============================================================================
// JSON and HTML report generation
// ============================================================================

#[test]
fn test_generate_json_report() {
    let reporter = ComplianceReporter::new(0.01);
    let kat_results = vec![passing_kat("ML-KEM-768 Test")];

    let report = reporter.generate_full_compliance_report(&kat_results, &None).unwrap();
    let json = reporter.generate_json_report(&report).unwrap();
    assert!(json.contains("report_id"));
    assert!(json.contains("algorithm_results"));
    assert!(json.contains("overall_compliance"));
}

#[test]
fn test_generate_html_report() {
    let reporter = ComplianceReporter::new(0.01);

    let kat_results = vec![passing_kat("ML-KEM-768 Test"), failing_kat("AES-GCM Test", "mismatch")];

    let report = reporter.generate_full_compliance_report(&kat_results, &None).unwrap();
    let html = reporter.generate_html_report(&report).unwrap();
    assert!(html.contains("<!DOCTYPE html>"));
    assert!(html.contains("Compliance Report"));
    assert!(html.contains("Algorithm Results"));
    assert!(html.contains("Recommendations"));
    assert!(html.contains("Statistical Testing Results"));
}

#[test]
fn test_generate_html_report_with_all_compliance_statuses() {
    let reporter = ComplianceReporter::new(0.01);

    let kat_results =
        vec![passing_kat("ML-KEM-768 Test 1"), failing_kat("ML-DSA-44 Test 1", "Failed")];

    let report = reporter.generate_full_compliance_report(&kat_results, &None).unwrap();
    let html = reporter.generate_html_report(&report).unwrap();
    assert!(html.contains("class=\""));
}

// ============================================================================
// ComplianceStatus and related types
// ============================================================================

#[test]
fn test_compliance_status_variants() {
    assert_eq!(ComplianceStatus::FullyCompliant, ComplianceStatus::FullyCompliant);
    assert_ne!(ComplianceStatus::FullyCompliant, ComplianceStatus::NonCompliant);
    assert_ne!(ComplianceStatus::PartiallyCompliant, ComplianceStatus::Unknown);

    let debug = format!("{:?}", ComplianceStatus::FullyCompliant);
    assert!(debug.contains("FullyCompliant"));
}

#[test]
fn test_randomness_quality_debug() {
    let qualities = vec![
        RandomnessQuality::Excellent,
        RandomnessQuality::Good,
        RandomnessQuality::Fair,
        RandomnessQuality::Poor,
        RandomnessQuality::Insufficient,
    ];
    for q in qualities {
        let debug = format!("{:?}", q);
        assert!(!debug.is_empty());
    }
}

#[test]
fn test_validation_scope_variants() {
    let module_scope = ValidationScope::Module;
    let debug = format!("{:?}", module_scope);
    assert!(debug.contains("Module"));

    let component_scope = ValidationScope::Component("test-component".to_string());
    let debug = format!("{:?}", component_scope);
    assert!(debug.contains("test-component"));
}

#[test]
fn test_security_coverage_fields() {
    let coverage = SecurityCoverage {
        post_quantum_supported: true,
        classical_supported: true,
        statistical_testing: true,
        timing_security: true,
        error_handling: true,
        memory_safety: true,
    };
    assert!(coverage.post_quantum_supported);
    assert!(coverage.classical_supported);

    let debug = format!("{:?}", coverage);
    assert!(debug.contains("true"));
}

#[test]
fn test_compliance_metrics_fields() {
    let metrics = ComplianceMetrics {
        total_test_cases: 100,
        passed_test_cases: 95,
        failed_test_cases: 5,
        pass_rate: 0.95,
        security_coverage: SecurityCoverage {
            post_quantum_supported: true,
            classical_supported: true,
            statistical_testing: true,
            timing_security: true,
            error_handling: true,
            memory_safety: true,
        },
        fips_level: "FIPS 140-3 Level 3".to_string(),
        validation_duration: Duration::from_secs(10),
    };
    assert_eq!(metrics.total_test_cases, 100);
    assert_eq!(metrics.pass_rate, 0.95);
}

// ============================================================================
// Compliance report serialization
// ============================================================================

#[test]
fn test_compliance_report_clone() {
    let reporter = ComplianceReporter::new(0.01);
    let kat_results = vec![passing_kat("ML-KEM-768 Test")];

    let report = reporter.generate_full_compliance_report(&kat_results, &None).unwrap();
    let cloned = report.clone();
    assert_eq!(cloned.report_id, report.report_id);
    assert_eq!(cloned.overall_compliance, report.overall_compliance);
}

#[test]
fn test_compliance_report_debug() {
    let reporter = ComplianceReporter::new(0.01);
    let kat_results = vec![passing_kat("ML-KEM-768 Test")];

    let report = reporter.generate_full_compliance_report(&kat_results, &None).unwrap();
    let debug = format!("{:?}", report);
    assert!(debug.contains("ComplianceReport"));
}

// ============================================================================
// Empty inputs and edge cases
// ============================================================================

#[test]
fn test_generate_full_compliance_report_empty_results() {
    let reporter = ComplianceReporter::new(0.01);
    let kat_results: Vec<KatResult> = vec![];
    let _result = reporter.generate_full_compliance_report(&kat_results, &None);
}

#[test]
fn test_statistical_compliance_result_clone() {
    let result = StatisticalComplianceResult {
        nist_sp800_22_tests: vec!["Frequency Test".to_string()],
        entropy_estimate: 7.9,
        randomness_quality: RandomnessQuality::Excellent,
        bits_tested: 8000,
        test_coverage: "Complete".to_string(),
    };
    let cloned = result.clone();
    assert_eq!(cloned.entropy_estimate, 7.9);
    assert_eq!(cloned.bits_tested, 8000);
}

// ============================================================================
// Additional coverage: partial compliance, many algorithm types
// ============================================================================

#[test]
fn test_generate_report_partial_compliance() {
    let reporter = ComplianceReporter::new(0.01);

    // Mix of pass and fail across different algorithms
    let kat_results = vec![
        passing_kat("ML-KEM-768 Encap Test"),
        passing_kat("ML-KEM-768 Decap Test"),
        failing_kat("ML-DSA-65 Sign Test", "signature mismatch"),
        passing_kat("AES-GCM-256 Encrypt Test"),
        passing_kat("SHA3-512 Hash Test"),
    ];

    let report = reporter.generate_full_compliance_report(&kat_results, &None).unwrap();
    // Should be partially compliant (some pass, some fail)
    assert!(
        report.overall_compliance == ComplianceStatus::PartiallyCompliant
            || report.overall_compliance == ComplianceStatus::NonCompliant
    );
}

#[test]
fn test_generate_report_all_algorithms_passing() {
    let reporter = ComplianceReporter::new(0.01);

    let kat_results = vec![
        passing_kat("ML-KEM-512 Test"),
        passing_kat("ML-KEM-768 Test"),
        passing_kat("ML-KEM-1024 Test"),
        passing_kat("ML-DSA-44 Test"),
        passing_kat("ML-DSA-65 Test"),
        passing_kat("ML-DSA-87 Test"),
        passing_kat("SLH-DSA-128s Test"),
        passing_kat("SLH-DSA-256f Test"),
        passing_kat("AES-GCM-128 Test"),
        passing_kat("AES-GCM-256 Test"),
        passing_kat("SHA-256 Test"),
        passing_kat("SHA3-256 Test"),
        passing_kat("Ed25519 Test"),
        passing_kat("X25519 Test"),
        passing_kat("HYBRID-KEM Test"),
        passing_kat("ChaCha20-Poly1305 Test"),
    ];

    let report = reporter.generate_full_compliance_report(&kat_results, &None).unwrap();
    // All KATs pass but overall compliance depends on statistical and FIPS scores too
    assert!(report.algorithm_results.len() >= 5);
    assert!(report.security_level > 0);
}

#[test]
fn test_generate_report_fully_compliant_with_fips() {
    let reporter = ComplianceReporter::new(0.01);

    let kat_results = vec![
        passing_kat("ML-KEM-768 Test"),
        passing_kat("ML-DSA-44 Test"),
        passing_kat("SLH-DSA-128s Test"),
        passing_kat("AES-GCM-256 Test"),
        passing_kat("Ed25519 Test"),
    ];

    let fips_result = Fips140_3ValidationResult {
        validation_id: "full-compliance-test".to_string(),
        timestamp: Utc::now(),
        power_up_tests: vec![],
        conditional_tests: vec![],
        overall_passed: true,
        compliance_level: "FIPS 140-3 Level 3".to_string(),
        module_name: "FullComplianceModule".to_string(),
        execution_time: Duration::from_millis(100),
        detailed_results: serde_json::json!({}),
    };

    let report =
        reporter.generate_full_compliance_report(&kat_results, &Some(fips_result)).unwrap();
    // With FIPS validation + passing KATs, compliance should be at least partial
    assert!(
        report.overall_compliance == ComplianceStatus::PartiallyCompliant
            || report.overall_compliance == ComplianceStatus::FullyCompliant
    );
    assert!(report.fips_validation.is_some());
}

#[test]
fn test_generate_html_report_with_fips_validation() {
    let reporter = ComplianceReporter::new(0.01);
    let kat_results = vec![passing_kat("ML-KEM-768 Test")];

    let fips_result = Fips140_3ValidationResult {
        validation_id: "fips-html-test".to_string(),
        timestamp: Utc::now(),
        power_up_tests: vec![],
        conditional_tests: vec![],
        overall_passed: true,
        compliance_level: "FIPS 140-3 Level 1".to_string(),
        module_name: "HTMLTestModule".to_string(),
        execution_time: Duration::from_millis(50),
        detailed_results: serde_json::json!({"test": "data"}),
    };

    let report =
        reporter.generate_full_compliance_report(&kat_results, &Some(fips_result)).unwrap();
    let html = reporter.generate_html_report(&report).unwrap();
    assert!(html.contains("FIPS"));
}

#[test]
fn test_generate_json_report_with_failures() {
    let reporter = ComplianceReporter::new(0.01);
    let kat_results =
        vec![failing_kat("ML-KEM-768 Encap Test", "encap failed"), passing_kat("AES-GCM Test")];

    let report = reporter.generate_full_compliance_report(&kat_results, &None).unwrap();
    let json = reporter.generate_json_report(&report).unwrap();
    assert!(json.contains("recommendations"));
}
