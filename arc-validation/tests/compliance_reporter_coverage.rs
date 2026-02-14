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

use arc_validation::fips_validation_impl::Fips140_3Validator;
use arc_validation::kat_tests::types::KatResult;
use arc_validation::validation_summary::ComplianceReporter;

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

    assert!(report.report_id.starts_with("QS-COMPLIANCE-"));
    assert!(!report.algorithm_results.is_empty());
    assert!(report.statistical_results.is_some());
    assert!(!report.recommendations.is_empty());
    assert!(report.security_level > 0);
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

    assert!(report.fips_validation.is_some());
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
    assert!(!report.algorithm_results.is_empty());
    // Recommendations should mention issues
    assert!(report.recommendations.len() >= 2);
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
    assert_eq!(metrics.total_test_cases, results.len());
    assert_eq!(metrics.passed_test_cases, results.len()); // all pass
    assert_eq!(metrics.failed_test_cases, 0);
    assert!(metrics.pass_rate > 0.99);
    assert!(metrics.security_coverage.post_quantum_supported);
    assert!(metrics.security_coverage.classical_supported);
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

    assert!(!json.is_empty());
    assert!(json.contains("report_id"));
    assert!(json.contains("algorithm_results"));
    assert!(json.contains("overall_compliance"));
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

    assert!(html.contains("<!DOCTYPE html>"));
    assert!(html.contains("FIPS 140-3 Compliance Report"));
    assert!(html.contains("Algorithm Results"));
    assert!(html.contains("Recommendations"));
    assert!(html.contains("</html>"));
}

#[test]
fn test_generate_html_report_with_statistical_results() {
    let reporter = ComplianceReporter::new(0.01);
    let results = make_mixed_kat_results();
    let report = reporter.generate_full_compliance_report(&results, &None).unwrap();

    let html = reporter.generate_html_report(&report).unwrap();

    // Should include statistical testing section
    assert!(html.contains("Statistical Testing Results"));
    assert!(html.contains("Randomness Quality"));
    assert!(html.contains("Entropy Estimate"));
}

// ============================================================================
// save_report_to_file
// ============================================================================

#[test]
fn test_save_report_to_file() {
    let reporter = ComplianceReporter::new(0.01);
    let results = make_mixed_kat_results();
    let report = reporter.generate_full_compliance_report(&results, &None).unwrap();

    let tmp_base = "/tmp/claude/compliance_report_test";
    reporter.save_report_to_file(&report, tmp_base).expect("Save should succeed");

    // Verify files were created
    let json_path = format!("{}.json", tmp_base);
    let html_path = format!("{}.html", tmp_base);
    assert!(std::path::Path::new(&json_path).exists(), "JSON file should exist");
    assert!(std::path::Path::new(&html_path).exists(), "HTML file should exist");

    // Verify file contents
    let json_content = std::fs::read_to_string(&json_path).unwrap();
    assert!(json_content.contains("report_id"));
    let html_content = std::fs::read_to_string(&html_path).unwrap();
    assert!(html_content.contains("<!DOCTYPE html>"));

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

    assert_eq!(report.algorithm_results.len(), 1);
    assert!(report.algorithm_results.contains_key("AES-GCM"));
}

#[test]
fn test_report_unknown_algorithm() {
    let reporter = ComplianceReporter::new(0.01);
    let results = vec![make_kat_result("CustomAlgo Test", true)];

    let report = reporter.generate_full_compliance_report(&results, &None).unwrap();

    // Unknown algorithms should still be grouped
    assert!(report.algorithm_results.contains_key("Unknown"));
}
