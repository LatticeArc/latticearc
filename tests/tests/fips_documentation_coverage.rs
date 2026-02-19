#![deny(unsafe_code)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::panic)]
#![allow(clippy::indexing_slicing)]
#![allow(clippy::arithmetic_side_effects)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::float_cmp)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_sign_loss)]
#![allow(missing_docs)]

//! Coverage tests for `NistDocumentationGenerator` in cavp/documentation.rs.

use chrono::Utc;
use latticearc_tests::validation::cavp::compliance::{
    CavpComplianceReport, ComplianceCriteria, ComplianceStatus, ComplianceTestResult,
    MemoryUsageMetrics, PerformanceMetrics, SecurityRequirement, TestCategory, TestResult,
    TestSummary, ThroughputMetrics,
};
use latticearc_tests::validation::cavp::documentation::NistDocumentationGenerator;
use latticearc_tests::validation::cavp::types::CavpAlgorithm;
use std::collections::HashMap;

// ============================================================================
// Helper: build a CavpComplianceReport with configurable fields
// ============================================================================

fn make_report(
    algorithm: CavpAlgorithm,
    status: ComplianceStatus,
    total: usize,
    passed: usize,
    pass_rate: f64,
    security_level: usize,
    coverage: f64,
    detailed: Vec<ComplianceTestResult>,
    security_reqs: Vec<SecurityRequirement>,
    nist_standards: Vec<String>,
) -> CavpComplianceReport {
    CavpComplianceReport {
        report_id: "CAVP-TEST-001".to_string(),
        algorithm,
        timestamp: Utc::now(),
        compliance_status: status,
        summary: TestSummary {
            total_tests: total,
            passed_tests: passed,
            failed_tests: total - passed,
            pass_rate,
            security_level,
            coverage,
        },
        detailed_results: detailed,
        performance_metrics: PerformanceMetrics {
            avg_execution_time_ms: 1.5,
            min_execution_time_ms: 1,
            max_execution_time_ms: 3,
            total_execution_time_ms: 15,
            memory_usage: MemoryUsageMetrics {
                peak_memory_bytes: 1024,
                avg_memory_bytes: 512,
                efficiency_rating: 0.85,
            },
            throughput: ThroughputMetrics {
                operations_per_second: 1000.0,
                bytes_per_second: 1024,
                latency_percentiles: {
                    let mut p = HashMap::new();
                    p.insert("p50".to_string(), 1.0);
                    p.insert("p95".to_string(), 2.5);
                    p.insert("p99".to_string(), 3.0);
                    p
                },
            },
        },
        compliance_criteria: ComplianceCriteria {
            min_pass_rate: 100.0,
            max_execution_time_ms: 5000,
            min_coverage: 95.0,
            security_requirements: security_reqs,
        },
        nist_standards,
    }
}

fn make_simple_report(status: ComplianceStatus, pass_rate: f64) -> CavpComplianceReport {
    make_report(
        CavpAlgorithm::MlKem { variant: "768".to_string() },
        status,
        10,
        if pass_rate == 100.0 { 10 } else { (pass_rate / 10.0) as usize },
        pass_rate,
        192,
        95.0,
        vec![],
        vec![],
        vec!["FIPS 203".to_string()],
    )
}

fn make_security_req(id: &str, mandatory: bool) -> SecurityRequirement {
    SecurityRequirement {
        requirement_id: id.to_string(),
        description: format!("Security requirement {}", id),
        mandatory,
        test_methods: vec!["KAT".to_string(), "CAVP".to_string()],
    }
}

fn make_detailed_result(
    test_id: &str,
    result: TestResult,
    details: HashMap<String, String>,
) -> ComplianceTestResult {
    ComplianceTestResult {
        test_id: test_id.to_string(),
        category: TestCategory::Correctness,
        description: format!("Test {}", test_id),
        result,
        execution_time_ms: 5,
        details,
    }
}

// ============================================================================
// NistDocumentationGenerator constructors
// ============================================================================

#[test]
fn test_generator_new() {
    let dg = NistDocumentationGenerator::new(
        "TestOrg".to_string(),
        "TestModule".to_string(),
        "2.0.0".to_string(),
    );
    assert_eq!(dg.organization, "TestOrg");
    assert_eq!(dg.module_name, "TestModule");
    assert_eq!(dg.module_version, "2.0.0");
    assert_eq!(dg.certificate_authority, "NIST CAVP");
}

#[test]
fn test_generator_default() {
    let dg = NistDocumentationGenerator::default();
    assert_eq!(dg.organization, "LatticeArc Project");
    assert_eq!(dg.module_name, "LatticeArc Validation");
    assert_eq!(dg.module_version, "1.0.0");
    assert_eq!(dg.certificate_authority, "NIST CAVP");
}

// ============================================================================
// generate_compliance_certificate
// ============================================================================

#[test]
fn test_certificate_basic_header() {
    let dg = NistDocumentationGenerator::default();
    let report = make_simple_report(ComplianceStatus::FullyCompliant, 100.0);
    let cert = dg.generate_compliance_certificate(&report).unwrap();

    assert!(cert.contains("NIST CAVP COMPLIANCE CERTIFICATE"));
    assert!(cert.contains("Module: LatticeArc Validation"));
    assert!(cert.contains("Version: 1.0.0"));
    assert!(cert.contains("Organization: LatticeArc Project"));
    assert!(cert.contains("Algorithm: ML-KEM-768"));
    assert!(cert.contains("FIPS Standard: FIPS 203"));
    assert!(cert.contains("Certificate ID: CAVP-TEST-001"));
    assert!(cert.contains("FULLY COMPLIANT"));
}

#[test]
fn test_certificate_test_summary() {
    let dg = NistDocumentationGenerator::default();
    let report = make_simple_report(ComplianceStatus::FullyCompliant, 100.0);
    let cert = dg.generate_compliance_certificate(&report).unwrap();

    assert!(cert.contains("TEST SUMMARY"));
    assert!(cert.contains("Total Tests: 10"));
    assert!(cert.contains("Passed Tests: 10"));
    assert!(cert.contains("Failed Tests: 0"));
    assert!(cert.contains("Pass Rate: 100.00%"));
    assert!(cert.contains("Security Level: 192 bits"));
}

#[test]
fn test_certificate_performance_metrics() {
    let dg = NistDocumentationGenerator::default();
    let report = make_simple_report(ComplianceStatus::FullyCompliant, 100.0);
    let cert = dg.generate_compliance_certificate(&report).unwrap();

    assert!(cert.contains("PERFORMANCE METRICS"));
    assert!(cert.contains("Avg Execution Time: 1.50 ms"));
    assert!(cert.contains("Min Execution Time: 1 ms"));
    assert!(cert.contains("Max Execution Time: 3 ms"));
    assert!(cert.contains("Total Execution Time: 15 ms"));
    assert!(cert.contains("Operations/sec: 1000.00"));
}

#[test]
fn test_certificate_compliance_criteria() {
    let dg = NistDocumentationGenerator::default();
    let report = make_simple_report(ComplianceStatus::FullyCompliant, 100.0);
    let cert = dg.generate_compliance_certificate(&report).unwrap();

    assert!(cert.contains("COMPLIANCE REQUIREMENTS"));
    assert!(cert.contains("Min Pass Rate Required: 100.0%"));
    assert!(cert.contains("Max Execution Time: 5000 ms"));
    assert!(cert.contains("Min Coverage Required: 95.0%"));
}

#[test]
fn test_certificate_with_security_requirements() {
    let dg = NistDocumentationGenerator::default();
    let reqs = vec![make_security_req("SEC-001", true), make_security_req("SEC-002", false)];
    let report = make_report(
        CavpAlgorithm::MlDsa { variant: "65".to_string() },
        ComplianceStatus::FullyCompliant,
        5,
        5,
        100.0,
        192,
        95.0,
        vec![],
        reqs,
        vec!["FIPS 204".to_string()],
    );
    let cert = dg.generate_compliance_certificate(&report).unwrap();

    assert!(cert.contains("SECURITY REQUIREMENTS"));
    assert!(cert.contains("SEC-001"));
    assert!(cert.contains("Mandatory: Yes"));
    assert!(cert.contains("SEC-002"));
    assert!(cert.contains("Mandatory: No"));
    assert!(cert.contains("Test Methods: KAT, CAVP"));
}

#[test]
fn test_certificate_with_detailed_results() {
    let dg = NistDocumentationGenerator::default();
    let detailed = vec![
        make_detailed_result("T-001", TestResult::Passed, HashMap::new()),
        make_detailed_result("T-002", TestResult::Failed("mismatch".to_string()), HashMap::new()),
        make_detailed_result(
            "T-003",
            TestResult::Skipped("not applicable".to_string()),
            HashMap::new(),
        ),
        make_detailed_result("T-004", TestResult::Error("timeout".to_string()), HashMap::new()),
    ];
    let report = make_report(
        CavpAlgorithm::SlhDsa { variant: "256".to_string() },
        ComplianceStatus::PartiallyCompliant { exceptions: vec!["T-002 failed".to_string()] },
        4,
        1,
        25.0,
        256,
        95.0,
        detailed,
        vec![],
        vec!["FIPS 205".to_string()],
    );
    let cert = dg.generate_compliance_certificate(&report).unwrap();

    assert!(cert.contains("VALIDATION DETAILS"));
    assert!(cert.contains("[PASSED] T-001"));
    assert!(cert.contains("[FAILED - mismatch] T-002"));
    assert!(cert.contains("[SKIPPED - not applicable] T-003"));
    assert!(cert.contains("[ERROR - timeout] T-004"));
}

#[test]
fn test_certificate_footer() {
    let dg = NistDocumentationGenerator::default();
    let report = make_simple_report(ComplianceStatus::FullyCompliant, 100.0);
    let cert = dg.generate_compliance_certificate(&report).unwrap();

    assert!(cert.contains("CERTIFICATION AUTHORITY"));
    assert!(cert.contains("This certificate issued by: NIST CAVP"));
    assert!(cert.contains("DIGITAL SIGNATURE"));
}

// ============================================================================
// generate_technical_report
// ============================================================================

#[test]
fn test_technical_report_header() {
    let dg = NistDocumentationGenerator::default();
    let report = make_simple_report(ComplianceStatus::FullyCompliant, 100.0);
    let tech = dg.generate_technical_report(&report).unwrap();

    assert!(tech.contains("NIST CAVP TECHNICAL VALIDATION REPORT"));
    assert!(tech.contains("Report ID: CAVP-TEST-001"));
    assert!(tech.contains("Algorithm: ML-KEM-768 (FIPS 203)"));
    assert!(tech.contains("Module: LatticeArc Validation v1.0.0"));
    assert!(tech.contains("Organization: LatticeArc Project"));
}

#[test]
fn test_technical_report_executive_summary() {
    let dg = NistDocumentationGenerator::default();
    let report = make_simple_report(ComplianceStatus::FullyCompliant, 100.0);
    let tech = dg.generate_technical_report(&report).unwrap();

    assert!(tech.contains("EXECUTIVE SUMMARY"));
    assert!(tech.contains("Overall Status: FULLY COMPLIANT"));
    assert!(tech.contains("Compliance Level: 100.0%"));
    assert!(tech.contains("Security Level: 192 bits"));
}

#[test]
fn test_technical_report_detailed_results_with_details() {
    let dg = NistDocumentationGenerator::default();
    let mut details = HashMap::new();
    details.insert("vector_id".to_string(), "V001".to_string());
    details.insert("input_size".to_string(), "32".to_string());
    let detailed = vec![make_detailed_result("D-001", TestResult::Passed, details)];
    let report = make_report(
        CavpAlgorithm::FnDsa { variant: "512".to_string() },
        ComplianceStatus::FullyCompliant,
        1,
        1,
        100.0,
        128,
        95.0,
        detailed,
        vec![],
        vec!["FIPS 206".to_string()],
    );
    let tech = dg.generate_technical_report(&report).unwrap();

    assert!(tech.contains("DETAILED TEST RESULTS"));
    assert!(tech.contains("Test ID: D-001"));
    assert!(tech.contains("Result: PASSED"));
    assert!(tech.contains("Additional Details:"));
}

#[test]
fn test_technical_report_performance_analysis() {
    let dg = NistDocumentationGenerator::default();
    let report = make_simple_report(ComplianceStatus::FullyCompliant, 100.0);
    let tech = dg.generate_technical_report(&report).unwrap();

    assert!(tech.contains("PERFORMANCE ANALYSIS"));
    assert!(tech.contains("Mean: 1.50 ms"));
    assert!(tech.contains("Min: 1 ms"));
    assert!(tech.contains("Max: 3 ms"));
    assert!(tech.contains("Memory Usage:"));
    assert!(tech.contains("Peak: 1024 bytes"));
    assert!(tech.contains("Average: 512 bytes"));
    assert!(tech.contains("Efficiency: 85.0%"));
    assert!(tech.contains("Throughput Metrics:"));
    assert!(tech.contains("Operations/sec: 1000.00"));
    assert!(tech.contains("Bytes/sec: 1024"));
}

#[test]
fn test_technical_report_compliance_analysis_met() {
    let dg = NistDocumentationGenerator::default();
    let report = make_simple_report(ComplianceStatus::FullyCompliant, 100.0);
    let tech = dg.generate_technical_report(&report).unwrap();

    assert!(tech.contains("COMPLIANCE ANALYSIS"));
    assert!(tech.contains("Required Pass Rate: 100.0%"));
    assert!(tech.contains("Achieved Pass Rate: 100.0%"));
    assert!(tech.contains("Compliance Met: Yes"));
}

#[test]
fn test_technical_report_compliance_analysis_not_met() {
    let dg = NistDocumentationGenerator::default();
    let report = make_simple_report(
        ComplianceStatus::NonCompliant { failures: vec!["low pass rate".to_string()] },
        50.0,
    );
    let tech = dg.generate_technical_report(&report).unwrap();

    assert!(tech.contains("Compliance Met: No"));
}

#[test]
fn test_technical_report_security_requirements_mandatory() {
    let dg = NistDocumentationGenerator::default();
    let reqs = vec![make_security_req("REQ-M1", true)];
    let report = make_report(
        CavpAlgorithm::MlKem { variant: "512".to_string() },
        ComplianceStatus::FullyCompliant,
        5,
        5,
        100.0,
        128,
        95.0,
        vec![],
        reqs,
        vec!["FIPS 203".to_string()],
    );
    let tech = dg.generate_technical_report(&report).unwrap();

    assert!(tech.contains("SECURITY REQUIREMENTS VERIFICATION"));
    assert!(tech.contains("Requirement: REQ-M1"));
    assert!(tech.contains("Mandatory: Yes"));
    assert!(tech.contains("VERIFIED (Mandatory requirement met)"));
}

#[test]
fn test_technical_report_security_requirements_optional() {
    let dg = NistDocumentationGenerator::default();
    let reqs = vec![make_security_req("REQ-O1", false)];
    let report = make_report(
        CavpAlgorithm::MlKem { variant: "512".to_string() },
        ComplianceStatus::FullyCompliant,
        5,
        5,
        100.0,
        128,
        95.0,
        vec![],
        reqs,
        vec!["FIPS 203".to_string()],
    );
    let tech = dg.generate_technical_report(&report).unwrap();

    assert!(tech.contains("VERIFIED (Optional requirement)"));
}

#[test]
fn test_technical_report_nist_standards() {
    let dg = NistDocumentationGenerator::default();
    let report = make_report(
        CavpAlgorithm::HybridKem,
        ComplianceStatus::FullyCompliant,
        5,
        5,
        100.0,
        256,
        95.0,
        vec![],
        vec![],
        vec!["FIPS 203".to_string(), "FIPS 197".to_string()],
    );
    let tech = dg.generate_technical_report(&report).unwrap();

    assert!(tech.contains("NIST STANDARDS COMPLIANCE"));
    assert!(tech.contains("FIPS 203 - FULLY COMPLIANT"));
    assert!(tech.contains("FIPS 197 - FULLY COMPLIANT"));
}

#[test]
fn test_technical_report_recommendations_perfect() {
    let dg = NistDocumentationGenerator::default();
    let report = make_simple_report(ComplianceStatus::FullyCompliant, 100.0);
    let tech = dg.generate_technical_report(&report).unwrap();

    assert!(tech.contains("RECOMMENDATIONS"));
    assert!(tech.contains("All tests passed"));
    assert!(tech.contains("periodic re-validation"));
}

#[test]
fn test_technical_report_recommendations_minor_issues() {
    let dg = NistDocumentationGenerator::default();
    let report = make_simple_report(ComplianceStatus::FullyCompliant, 97.0);
    let tech = dg.generate_technical_report(&report).unwrap();

    assert!(tech.contains("Minor issues detected"));
    assert!(tech.contains("Address specific failures"));
}

#[test]
fn test_technical_report_recommendations_significant_issues() {
    let dg = NistDocumentationGenerator::default();
    let report = make_simple_report(
        ComplianceStatus::NonCompliant { failures: vec!["critical failure".to_string()] },
        50.0,
    );
    let tech = dg.generate_technical_report(&report).unwrap();

    assert!(tech.contains("Significant compliance issues"));
    assert!(tech.contains("Comprehensive review and remediation"));
}

#[test]
fn test_technical_report_appendix() {
    let dg = NistDocumentationGenerator::default();
    let report = make_simple_report(ComplianceStatus::FullyCompliant, 100.0);
    let tech = dg.generate_technical_report(&report).unwrap();

    assert!(tech.contains("APPENDIX"));
    assert!(tech.contains("Test Environment:"));
    assert!(tech.contains("OS: Linux/Unix compatible"));
    assert!(tech.contains("Architecture: x86_64"));
}

// ============================================================================
// generate_audit_trail
// ============================================================================

#[test]
fn test_audit_trail_empty_reports() {
    let dg = NistDocumentationGenerator::default();
    let trail = dg.generate_audit_trail(&[]).unwrap();

    assert!(trail.contains("NIST CAVP AUDIT TRAIL"));
    assert!(trail.contains("Module: LatticeArc Validation v1.0.0"));
    assert!(trail.contains("Total Validations: 0"));
    assert!(trail.contains("Overall Pass Rate: 0.0%"));
}

#[test]
fn test_audit_trail_single_report() {
    let dg = NistDocumentationGenerator::default();
    let report = make_simple_report(ComplianceStatus::FullyCompliant, 100.0);
    let trail = dg.generate_audit_trail(&[report]).unwrap();

    assert!(trail.contains("VALIDATION HISTORY"));
    assert!(trail.contains("1. ML-KEM-768 Validation"));
    assert!(trail.contains("Report ID: CAVP-TEST-001"));
    assert!(trail.contains("Status: FULLY COMPLIANT"));
    assert!(trail.contains("Pass Rate: 100.0%"));
    assert!(trail.contains("Tests: 10 passed / 10 total"));
}

#[test]
fn test_audit_trail_partially_compliant() {
    let dg = NistDocumentationGenerator::default();
    let report = make_simple_report(
        ComplianceStatus::PartiallyCompliant {
            exceptions: vec!["Test T-003 edge case".to_string(), "Test T-007 timing".to_string()],
        },
        90.0,
    );
    let trail = dg.generate_audit_trail(&[report]).unwrap();

    assert!(trail.contains("PARTIALLY COMPLIANT"));
    assert!(trail.contains("Exceptions:"));
    assert!(trail.contains("Test T-003 edge case"));
    assert!(trail.contains("Test T-007 timing"));
}

#[test]
fn test_audit_trail_non_compliant() {
    let dg = NistDocumentationGenerator::default();
    let report = make_simple_report(
        ComplianceStatus::NonCompliant { failures: vec!["Critical security failure".to_string()] },
        40.0,
    );
    let trail = dg.generate_audit_trail(&[report]).unwrap();

    assert!(trail.contains("NON-COMPLIANT"));
    assert!(trail.contains("Failures:"));
    assert!(trail.contains("Critical security failure"));
}

#[test]
fn test_audit_trail_compliance_trends_improvement() {
    let dg = NistDocumentationGenerator::default();
    let r1 = make_simple_report(ComplianceStatus::FullyCompliant, 90.0);
    let r2 = make_simple_report(ComplianceStatus::FullyCompliant, 100.0);
    let trail = dg.generate_audit_trail(&[r1, r2]).unwrap();

    assert!(trail.contains("COMPLIANCE TRENDS"));
    assert!(trail.contains("Pass Rate Change:"));
    assert!(trail.contains("Improvement"));
}

#[test]
fn test_audit_trail_compliance_trends_decline() {
    let dg = NistDocumentationGenerator::default();
    let r1 = make_simple_report(ComplianceStatus::FullyCompliant, 100.0);
    let r2 = make_simple_report(
        ComplianceStatus::NonCompliant { failures: vec!["regression".to_string()] },
        80.0,
    );
    let trail = dg.generate_audit_trail(&[r1, r2]).unwrap();

    assert!(trail.contains("Decline"));
}

#[test]
fn test_audit_trail_summary_statistics() {
    let dg = NistDocumentationGenerator::default();
    let r1 = make_simple_report(ComplianceStatus::FullyCompliant, 100.0);
    let r2 = make_simple_report(
        ComplianceStatus::PartiallyCompliant { exceptions: vec!["minor".to_string()] },
        90.0,
    );
    let r3 = make_simple_report(
        ComplianceStatus::NonCompliant { failures: vec!["critical".to_string()] },
        50.0,
    );
    let trail = dg.generate_audit_trail(&[r1, r2, r3]).unwrap();

    assert!(trail.contains("SUMMARY STATISTICS"));
    assert!(trail.contains("Total Validations: 3"));
    assert!(trail.contains("Fully Compliant: 1"));
    assert!(trail.contains("Partially Compliant: 1"));
    assert!(trail.contains("Non-Compliant: 1"));
}

#[test]
fn test_audit_trail_certified_status() {
    let dg = NistDocumentationGenerator::default();
    let r1 = make_simple_report(ComplianceStatus::FullyCompliant, 100.0);
    let trail = dg.generate_audit_trail(&[r1]).unwrap();

    assert!(trail.contains("CERTIFICATION STATUS"));
    assert!(trail.contains("STATUS: CERTIFIED"));
    assert!(trail.contains("Module meets all NIST CAVP requirements"));
}

#[test]
fn test_audit_trail_conditionally_certified() {
    let dg = NistDocumentationGenerator::default();
    // Need total_passed/total_tests >= 95% but < 100%, and non_compliant == 0
    let r1 = make_report(
        CavpAlgorithm::MlKem { variant: "768".to_string() },
        ComplianceStatus::PartiallyCompliant { exceptions: vec!["minor".to_string()] },
        100,
        97,
        97.0,
        192,
        95.0,
        vec![],
        vec![],
        vec!["FIPS 203".to_string()],
    );
    let trail = dg.generate_audit_trail(&[r1]).unwrap();

    assert!(trail.contains("STATUS: CONDITIONALLY CERTIFIED"));
    assert!(trail.contains("Module meets most requirements with minor exceptions"));
}

#[test]
fn test_audit_trail_not_certified() {
    let dg = NistDocumentationGenerator::default();
    let r1 = make_simple_report(
        ComplianceStatus::NonCompliant { failures: vec!["major failure".to_string()] },
        50.0,
    );
    let trail = dg.generate_audit_trail(&[r1]).unwrap();

    assert!(trail.contains("STATUS: NOT CERTIFIED"));
    assert!(trail.contains("Module does not meet NIST CAVP requirements"));
}

// ============================================================================
// format_compliance_status (tested indirectly)
// ============================================================================

#[test]
fn test_format_compliance_status_all_variants() {
    let dg = NistDocumentationGenerator::default();

    let fully = make_simple_report(ComplianceStatus::FullyCompliant, 100.0);
    let cert_fully = dg.generate_compliance_certificate(&fully).unwrap();
    assert!(cert_fully.contains("FULLY COMPLIANT"));

    let partial = make_simple_report(
        ComplianceStatus::PartiallyCompliant {
            exceptions: vec!["e1".to_string(), "e2".to_string()],
        },
        90.0,
    );
    let cert_partial = dg.generate_compliance_certificate(&partial).unwrap();
    assert!(cert_partial.contains("PARTIALLY COMPLIANT (2 exceptions)"));

    let non = make_simple_report(
        ComplianceStatus::NonCompliant { failures: vec!["f1".to_string()] },
        50.0,
    );
    let cert_non = dg.generate_compliance_certificate(&non).unwrap();
    assert!(cert_non.contains("NON-COMPLIANT (1 failures)"));

    let insufficient = make_simple_report(ComplianceStatus::InsufficientData, 0.0);
    let cert_insuf = dg.generate_compliance_certificate(&insufficient).unwrap();
    assert!(cert_insuf.contains("INSUFFICIENT DATA"));
}

// ============================================================================
// format_test_result (tested indirectly via certificate detailed results)
// ============================================================================

#[test]
fn test_format_test_result_all_variants() {
    let dg = NistDocumentationGenerator::default();
    let detailed = vec![
        make_detailed_result("R-P", TestResult::Passed, HashMap::new()),
        make_detailed_result("R-F", TestResult::Failed("bad".to_string()), HashMap::new()),
        make_detailed_result("R-S", TestResult::Skipped("skip".to_string()), HashMap::new()),
        make_detailed_result("R-E", TestResult::Error("err".to_string()), HashMap::new()),
    ];
    let report = make_report(
        CavpAlgorithm::MlKem { variant: "1024".to_string() },
        ComplianceStatus::FullyCompliant,
        4,
        1,
        25.0,
        256,
        95.0,
        detailed,
        vec![],
        vec![],
    );
    let cert = dg.generate_compliance_certificate(&report).unwrap();

    assert!(cert.contains("[PASSED] R-P"));
    assert!(cert.contains("[FAILED - bad] R-F"));
    assert!(cert.contains("[SKIPPED - skip] R-S"));
    assert!(cert.contains("[ERROR - err] R-E"));
}

// ============================================================================
// Different algorithms
// ============================================================================

#[test]
fn test_certificate_with_different_algorithms() {
    let dg = NistDocumentationGenerator::default();

    let algorithms = vec![
        (CavpAlgorithm::MlKem { variant: "512".to_string() }, "ML-KEM-512", "FIPS 203"),
        (CavpAlgorithm::MlDsa { variant: "44".to_string() }, "ML-DSA-44", "FIPS 204"),
        (CavpAlgorithm::SlhDsa { variant: "128".to_string() }, "SLH-DSA-128", "FIPS 205"),
        (CavpAlgorithm::FnDsa { variant: "1024".to_string() }, "FN-DSA-1024", "FIPS 206"),
        (CavpAlgorithm::HybridKem, "Hybrid-KEM", "FIPS 203 + FIPS 197"),
    ];

    for (algo, name, standard) in algorithms {
        let report = make_report(
            algo,
            ComplianceStatus::FullyCompliant,
            1,
            1,
            100.0,
            128,
            95.0,
            vec![],
            vec![],
            vec![standard.to_string()],
        );
        let cert = dg.generate_compliance_certificate(&report).unwrap();
        assert!(cert.contains(&format!("Algorithm: {}", name)));
        assert!(cert.contains(&format!("FIPS Standard: {}", standard)));
    }
}
