#![deny(unsafe_code)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::panic)]
#![allow(clippy::indexing_slicing)]
#![allow(clippy::arithmetic_side_effects)]
#![allow(clippy::cast_precision_loss)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::drop_non_drop)]
#![allow(missing_docs)]

//! Coverage tests for `ComplianceReporter` methods in validation_summary.rs.
//!
//! Targets: `generate_full_compliance_report()`, `generate_html_report()`,
//! `generate_json_report()`, `save_report_to_file()`, and internal helpers.

use latticearc_tests::validation::fips_validation_impl::Fips140_3Validator;
use latticearc_tests::validation::kat_tests::types::KatResult;
use latticearc_tests::validation::validation_summary::ComplianceReporter;

fn make_kat_result(test_case: &str, passed: bool) -> KatResult {
    KatResult {
        test_case: test_case.to_string(),
        passed,
        execution_time_ns: 1000,
        error_message: if passed { None } else { Some("test failure".to_string()) },
    }
}

fn make_mixed_kat_results() -> Vec<KatResult> {
    vec![
        make_kat_result("ML-KEM-1024 Encapsulate", true),
        make_kat_result("ML-KEM-1024 Decapsulate", true),
        make_kat_result("ML-DSA-44 Sign", true),
        make_kat_result("ML-DSA-44 Verify", true),
        make_kat_result("AES-GCM-256 Encrypt", true),
        make_kat_result("AES-GCM-256 Decrypt", true),
        make_kat_result("SHA3-256 Hash", true),
        make_kat_result("Ed25519 Sign", true),
        make_kat_result("Ed25519 Verify", true),
        make_kat_result("HYBRID-KEM Encap", true),
        make_kat_result("SLH-DSA-128s Sign", true),
    ]
}

// ============================================================================
// ComplianceReporter construction
// ============================================================================

#[test]
fn test_compliance_reporter_new() {
    let reporter = ComplianceReporter::new(0.01);
    // Construction should not panic
    drop(reporter);
}

#[test]
fn test_compliance_reporter_default() {
    let reporter = ComplianceReporter::default();
    drop(reporter);
}

// ============================================================================
// generate_full_compliance_report
// ============================================================================

#[test]
fn test_generate_full_compliance_report_all_pass() {
    let reporter = ComplianceReporter::new(0.01);
    let results = make_mixed_kat_results();

    let report = reporter
        .generate_full_compliance_report(&results, &None)
        .expect("Report generation should succeed");

    assert!(
        report.report_id.starts_with("QS-COMPLIANCE-"),
        "report_id should have QS-COMPLIANCE- prefix"
    );
    assert!(
        !report.algorithm_results.is_empty(),
        "algorithm_results should not be empty for mixed KAT input"
    );
    assert!(report.statistical_results.is_some(), "statistical_results should be present");
    assert!(!report.recommendations.is_empty(), "recommendations should not be empty");
    assert!(report.security_level > 0, "security_level should be positive for passing tests");
}

#[test]
fn test_generate_full_compliance_report_with_fips_validation() {
    let reporter = ComplianceReporter::new(0.01);
    let results = make_mixed_kat_results();

    let mut validator = Fips140_3Validator::default();
    let fips_result = validator.run_conditional_tests().expect("Conditional tests should succeed");

    let report = reporter
        .generate_full_compliance_report(&results, &Some(fips_result))
        .expect("Report with FIPS validation should succeed");

    assert!(
        report.fips_validation.is_some(),
        "fips_validation should be present when FIPS result provided"
    );
}

#[test]
fn test_generate_full_compliance_report_with_failures() {
    let reporter = ComplianceReporter::new(0.01);
    let results = vec![
        make_kat_result("ML-KEM-1024 Encapsulate", true),
        make_kat_result("ML-KEM-1024 Decapsulate", false),
        make_kat_result("AES-GCM-256 Encrypt", false),
        make_kat_result("AES-GCM-256 Decrypt", false),
    ];

    let report = reporter
        .generate_full_compliance_report(&results, &None)
        .expect("Report with failures should succeed");

    // Should have algorithm results for ML-KEM and AES-GCM
    assert!(
        !report.algorithm_results.is_empty(),
        "algorithm_results should not be empty even with failures"
    );
    // Recommendations should mention issues
    assert!(
        report.recommendations.len() >= 2,
        "should have at least 2 recommendations for 3 failures"
    );
}

#[test]
fn test_generate_full_compliance_report_algorithm_grouping() {
    let reporter = ComplianceReporter::new(0.01);
    let results = make_mixed_kat_results();

    let report = reporter.generate_full_compliance_report(&results, &None).unwrap();

    // Should group by algorithm type
    let keys: Vec<&String> = report.algorithm_results.keys().collect();
    assert!(
        keys.iter().any(|k| k.contains("ML-KEM") || k.contains("AES-GCM") || k.contains("Ed25519")),
        "Should group results by algorithm"
    );
}

#[test]
fn test_generate_full_compliance_report_metrics() {
    let reporter = ComplianceReporter::new(0.01);
    let results = make_mixed_kat_results();

    let report = reporter.generate_full_compliance_report(&results, &None).unwrap();

    let metrics = &report.detailed_metrics;
    assert_eq!(
        metrics.total_test_cases,
        results.len(),
        "total_test_cases should match input count"
    );
    assert_eq!(metrics.passed_test_cases, results.len(), "all test cases should pass");
    assert_eq!(metrics.failed_test_cases, 0, "no test cases should fail");
    assert!(metrics.pass_rate > 0.99, "pass_rate should be ~1.0 for all-passing input");
    assert!(
        metrics.security_coverage.post_quantum_supported,
        "PQ support should be detected from ML-KEM/ML-DSA tests"
    );
    assert!(
        metrics.security_coverage.classical_supported,
        "classical support should be detected from AES-GCM/Ed25519 tests"
    );
}

// ============================================================================
// generate_json_report
// ============================================================================

#[test]
fn test_generate_json_report() {
    let reporter = ComplianceReporter::new(0.01);
    let results = make_mixed_kat_results();
    let report = reporter.generate_full_compliance_report(&results, &None).unwrap();

    let json = reporter.generate_json_report(&report).expect("JSON report should succeed");

    assert!(!json.is_empty(), "JSON report should not be empty");
    assert!(json.contains("report_id"), "JSON should contain report_id field");
    assert!(json.contains("algorithm_results"), "JSON should contain algorithm_results field");
    assert!(json.contains("overall_compliance"), "JSON should contain overall_compliance field");
}

// ============================================================================
// generate_html_report
// ============================================================================

#[test]
fn test_generate_html_report() {
    let reporter = ComplianceReporter::new(0.01);
    let results = make_mixed_kat_results();
    let report = reporter.generate_full_compliance_report(&results, &None).unwrap();

    let html = reporter.generate_html_report(&report).expect("HTML report should succeed");

    assert!(html.contains("<!DOCTYPE html>"), "HTML should have DOCTYPE declaration");
    assert!(html.contains("FIPS 140-3 Compliance Report"), "HTML should contain report title");
    assert!(html.contains("Algorithm Results"), "HTML should contain Algorithm Results section");
    assert!(html.contains("Recommendations"), "HTML should contain Recommendations section");
    assert!(html.contains("</html>"), "HTML should have closing html tag");
}

#[test]
fn test_generate_html_report_with_statistical_results() {
    let reporter = ComplianceReporter::new(0.01);
    let results = make_mixed_kat_results();
    let report = reporter.generate_full_compliance_report(&results, &None).unwrap();

    let html = reporter.generate_html_report(&report).unwrap();

    // Should include statistical testing section
    assert!(
        html.contains("Statistical Testing Results"),
        "HTML should have Statistical Testing Results section"
    );
    assert!(html.contains("Randomness Quality"), "HTML should mention Randomness Quality");
    assert!(html.contains("Entropy Estimate"), "HTML should mention Entropy Estimate");
}

// ============================================================================
// save_report_to_file
// ============================================================================

#[test]
fn test_save_report_to_file() {
    let reporter = ComplianceReporter::new(0.01);
    let results = make_mixed_kat_results();
    let report = reporter.generate_full_compliance_report(&results, &None).unwrap();

    let tmp_dir = std::env::temp_dir().join("compliance_report_test_dir");
    std::fs::create_dir_all(&tmp_dir).expect("Should create temp dir");
    let tmp_base = tmp_dir.join("compliance_report_test");
    let tmp_base = tmp_base.to_str().expect("Valid UTF-8 path");
    reporter.save_report_to_file(&report, tmp_base).expect("Save should succeed");

    // Verify files were created
    let json_path = format!("{}.json", tmp_base);
    let html_path = format!("{}.html", tmp_base);
    assert!(std::path::Path::new(&json_path).exists(), "JSON file should exist");
    assert!(std::path::Path::new(&html_path).exists(), "HTML file should exist");

    // Verify file contents
    let json_content = std::fs::read_to_string(&json_path).unwrap();
    assert!(json_content.contains("report_id"), "saved JSON file should contain report_id");
    let html_content = std::fs::read_to_string(&html_path).unwrap();
    assert!(html_content.contains("<!DOCTYPE html>"), "saved HTML file should have DOCTYPE");

    // Cleanup
    let _ = std::fs::remove_file(&json_path);
    let _ = std::fs::remove_file(&html_path);
}

// ============================================================================
// Compliance status variations (exercises generate_recommendations branches)
// ============================================================================

#[test]
fn test_report_fully_compliant_recommendations() {
    let reporter = ComplianceReporter::new(0.01);
    // All passing tests should produce "FullyCompliant" recommendations
    let results = make_mixed_kat_results();
    let mut validator = Fips140_3Validator::default();
    let fips = validator.run_conditional_tests().unwrap();

    let report = reporter.generate_full_compliance_report(&results, &Some(fips)).unwrap();

    // Should have some recommendations regardless of compliance status
    assert!(!report.recommendations.is_empty(), "Report should always have recommendations");
}

#[test]
fn test_report_with_all_failures_recommendations() {
    let reporter = ComplianceReporter::new(0.01);
    let results = vec![
        make_kat_result("ML-KEM-1024 Fail", false),
        make_kat_result("AES-GCM-256 Fail", false),
        make_kat_result("Ed25519 Fail", false),
    ];

    let report = reporter.generate_full_compliance_report(&results, &None).unwrap();

    // Non-compliant should have critical recommendations
    let has_critical = report.recommendations.iter().any(|r| {
        r.contains("Critical") || r.contains("action required") || r.contains("Immediate")
    });
    assert!(
        has_critical || report.recommendations.len() >= 3,
        "Non-compliant should have critical recommendations"
    );
}

// ============================================================================
// Edge cases
// ============================================================================

#[test]
fn test_report_single_algorithm() {
    let reporter = ComplianceReporter::new(0.01);
    let results = vec![make_kat_result("AES-GCM-256 Encrypt", true)];

    let report = reporter.generate_full_compliance_report(&results, &None).unwrap();

    assert_eq!(report.algorithm_results.len(), 1, "single algorithm should produce 1 result group");
    assert!(
        report.algorithm_results.contains_key("AES-GCM"),
        "AES-GCM algorithm should be recognized and grouped"
    );
}

#[test]
fn test_report_unknown_algorithm() {
    let reporter = ComplianceReporter::new(0.01);
    let results = vec![make_kat_result("CustomAlgo Test", true)];

    let report = reporter.generate_full_compliance_report(&results, &None).unwrap();

    // Unknown algorithms should still be grouped
    assert!(
        report.algorithm_results.contains_key("Unknown"),
        "unrecognized algorithms should be grouped under 'Unknown'"
    );
}
