//! FIPS input/format/resource validation and documentation-generator
//! coverage tests.
//!
//! Covers `NistDocumentationGenerator` report generation and the
//! `latticearc_tests::validation` crate's input/output/format/resource-limit
//! validation functions.

#![deny(unsafe_code)]

mod documentation {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::arithmetic_side_effects)]
    #![allow(clippy::too_many_arguments)]
    #![allow(clippy::float_cmp)]
    #![allow(clippy::cast_possible_truncation)]
    #![allow(clippy::cast_sign_loss)]

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
    fn test_generator_new_sets_fields_succeeds() {
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
    fn test_generator_default_sets_expected_fields_succeeds() {
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
    fn test_certificate_basic_header_contains_expected_fields_succeeds() {
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
    fn test_certificate_test_summary_contains_expected_fields_succeeds() {
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
    fn test_certificate_performance_metrics_contains_expected_fields_succeeds() {
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
    fn test_certificate_compliance_criteria_contains_expected_fields_succeeds() {
        let dg = NistDocumentationGenerator::default();
        let report = make_simple_report(ComplianceStatus::FullyCompliant, 100.0);
        let cert = dg.generate_compliance_certificate(&report).unwrap();

        assert!(cert.contains("COMPLIANCE REQUIREMENTS"));
        assert!(cert.contains("Min Pass Rate Required: 100.0%"));
        assert!(cert.contains("Max Execution Time: 5000 ms"));
        assert!(cert.contains("Min Coverage Required: 95.0%"));
    }

    #[test]
    fn test_certificate_with_security_requirements_contains_expected_fields_succeeds() {
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
    fn test_certificate_with_detailed_results_formats_all_statuses_has_correct_size() {
        let dg = NistDocumentationGenerator::default();
        let detailed = vec![
            make_detailed_result("T-001", TestResult::Passed, HashMap::new()),
            make_detailed_result(
                "T-002",
                TestResult::Failed("mismatch".to_string()),
                HashMap::new(),
            ),
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
    fn test_certificate_footer_contains_expected_fields_succeeds() {
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
    fn test_technical_report_header_contains_expected_fields_succeeds() {
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
    fn test_technical_report_executive_summary_contains_expected_fields_succeeds() {
        let dg = NistDocumentationGenerator::default();
        let report = make_simple_report(ComplianceStatus::FullyCompliant, 100.0);
        let tech = dg.generate_technical_report(&report).unwrap();

        assert!(tech.contains("EXECUTIVE SUMMARY"));
        assert!(tech.contains("Overall Status: FULLY COMPLIANT"));
        assert!(tech.contains("Compliance Level: 100.0%"));
        assert!(tech.contains("Security Level: 192 bits"));
    }

    #[test]
    fn test_technical_report_detailed_results_with_details_contains_expected_fields_succeeds() {
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
    fn test_technical_report_performance_analysis_contains_expected_fields_succeeds() {
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
    fn test_technical_report_compliance_analysis_met_shows_yes_succeeds() {
        let dg = NistDocumentationGenerator::default();
        let report = make_simple_report(ComplianceStatus::FullyCompliant, 100.0);
        let tech = dg.generate_technical_report(&report).unwrap();

        assert!(tech.contains("COMPLIANCE ANALYSIS"));
        assert!(tech.contains("Required Pass Rate: 100.0%"));
        assert!(tech.contains("Achieved Pass Rate: 100.0%"));
        assert!(tech.contains("Compliance Met: Yes"));
    }

    #[test]
    fn test_technical_report_compliance_analysis_not_met_shows_no_succeeds() {
        let dg = NistDocumentationGenerator::default();
        let report = make_simple_report(
            ComplianceStatus::NonCompliant { failures: vec!["low pass rate".to_string()] },
            50.0,
        );
        let tech = dg.generate_technical_report(&report).unwrap();

        assert!(tech.contains("Compliance Met: No"));
    }

    #[test]
    fn test_technical_report_security_requirements_mandatory_shows_verified_succeeds() {
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
    fn test_technical_report_security_requirements_optional_shows_verified_succeeds() {
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
    fn test_technical_report_nist_standards_shows_fully_compliant_succeeds() {
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
    fn test_technical_report_recommendations_perfect_shows_all_passed_succeeds() {
        let dg = NistDocumentationGenerator::default();
        let report = make_simple_report(ComplianceStatus::FullyCompliant, 100.0);
        let tech = dg.generate_technical_report(&report).unwrap();

        assert!(tech.contains("RECOMMENDATIONS"));
        assert!(tech.contains("All tests passed"));
        assert!(tech.contains("periodic re-validation"));
    }

    #[test]
    fn test_technical_report_recommendations_minor_issues_shows_address_failures_fails() {
        let dg = NistDocumentationGenerator::default();
        let report = make_simple_report(ComplianceStatus::FullyCompliant, 97.0);
        let tech = dg.generate_technical_report(&report).unwrap();

        assert!(tech.contains("Minor issues detected"));
        assert!(tech.contains("Address specific failures"));
    }

    #[test]
    fn test_technical_report_recommendations_significant_issues_shows_comprehensive_review_succeeds()
     {
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
    fn test_technical_report_appendix_contains_expected_fields_succeeds() {
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
    fn test_audit_trail_empty_reports_shows_zero_totals_succeeds() {
        let dg = NistDocumentationGenerator::default();
        let trail = dg.generate_audit_trail(&[]).unwrap();

        assert!(trail.contains("NIST CAVP AUDIT TRAIL"));
        assert!(trail.contains("Module: LatticeArc Validation v1.0.0"));
        assert!(trail.contains("Total Validations: 0"));
        assert!(trail.contains("Overall Pass Rate: 0.0%"));
    }

    #[test]
    fn test_audit_trail_single_report_contains_expected_fields_succeeds() {
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
    fn test_audit_trail_partially_compliant_shows_exceptions_succeeds() {
        let dg = NistDocumentationGenerator::default();
        let report = make_simple_report(
            ComplianceStatus::PartiallyCompliant {
                exceptions: vec![
                    "Test T-003 edge case".to_string(),
                    "Test T-007 timing".to_string(),
                ],
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
    fn test_audit_trail_non_compliant_shows_failures_fails() {
        let dg = NistDocumentationGenerator::default();
        let report = make_simple_report(
            ComplianceStatus::NonCompliant {
                failures: vec!["Critical security failure".to_string()],
            },
            40.0,
        );
        let trail = dg.generate_audit_trail(&[report]).unwrap();

        assert!(trail.contains("NON-COMPLIANT"));
        assert!(trail.contains("Failures:"));
        assert!(trail.contains("Critical security failure"));
    }

    #[test]
    fn test_audit_trail_compliance_trends_improvement_shows_improvement_succeeds() {
        let dg = NistDocumentationGenerator::default();
        let r1 = make_simple_report(ComplianceStatus::FullyCompliant, 90.0);
        let r2 = make_simple_report(ComplianceStatus::FullyCompliant, 100.0);
        let trail = dg.generate_audit_trail(&[r1, r2]).unwrap();

        assert!(trail.contains("COMPLIANCE TRENDS"));
        assert!(trail.contains("Pass Rate Change:"));
        assert!(trail.contains("Improvement"));
    }

    #[test]
    fn test_audit_trail_compliance_trends_decline_shows_decline_succeeds() {
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
    fn test_audit_trail_summary_statistics_shows_counts_by_status_succeeds() {
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
    fn test_audit_trail_certified_status_shows_certified_succeeds() {
        let dg = NistDocumentationGenerator::default();
        let r1 = make_simple_report(ComplianceStatus::FullyCompliant, 100.0);
        let trail = dg.generate_audit_trail(&[r1]).unwrap();

        assert!(trail.contains("CERTIFICATION STATUS"));
        assert!(trail.contains("STATUS: CERTIFIED"));
        assert!(trail.contains("Module meets all NIST CAVP requirements"));
    }

    #[test]
    fn test_audit_trail_conditionally_certified_shows_conditionally_certified_succeeds() {
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
    fn test_audit_trail_not_certified_shows_not_certified_succeeds() {
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
    fn test_format_compliance_status_all_variants_produce_correct_strings_has_correct_size() {
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
    fn test_format_test_result_all_variants_produce_correct_strings_has_correct_size() {
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
    fn test_certificate_with_different_algorithms_succeeds() {
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
}

mod validation_comprehensive {
    //! Comprehensive tests for arc-validation crate
    //!
    //! This test suite covers:
    //! - Input validation (size, range)
    //! - Output validation and bounds checking
    //! - Format validation for cryptographic primitives
    //! - Resource limits validation
    //! - Timing-safe operations
    //! - Error handling

    #![allow(
        clippy::panic,
        clippy::unwrap_used,
        clippy::default_constructed_unit_structs,
        clippy::useless_vec
    )]

    use latticearc_tests::validation::{
        FormatError,
        ResourceError,
        // Resource limits
        ResourceLimits,
        ResourceLimitsManager,
        ValidationError,
        get_global_resource_limits,
        validate_decryption_size,
        validate_encryption_size,
        // Input validation
        validate_input_size,
        // Format validation
        validate_key_format,
        validate_signature_size,
    };

    // Import bounds module types with explicit paths
    use latticearc_tests::validation::bounds::{BoundsError, validate_bounds};
    use latticearc_tests::validation::output::{
        BoundsChecker, BoundsError as OutputBoundsError, OutputError, OutputValidator,
        SimpleValidator,
    };

    // ============================================================================
    // Input Validation Tests
    // ============================================================================

    mod input_validation_tests {
        use super::*;

        #[test]
        fn test_validate_input_size_valid_passes_validation() {
            let input = vec![0u8; 32];
            assert!(validate_input_size(&input, 16, 64).is_ok());
        }

        #[test]
        fn test_validate_input_size_exact_min_passes_validation() {
            let input = vec![0u8; 16];
            assert!(validate_input_size(&input, 16, 64).is_ok());
        }

        #[test]
        fn test_validate_input_size_exact_max_passes_validation() {
            let input = vec![0u8; 64];
            assert!(validate_input_size(&input, 16, 64).is_ok());
        }

        #[test]
        fn test_validate_input_size_too_small_fails() {
            let input = vec![0u8; 8];
            let result = validate_input_size(&input, 16, 64);
            assert!(result.is_err());
            match result.unwrap_err() {
                ValidationError::InputTooSmall(actual, min) => {
                    assert_eq!(actual, 8);
                    assert_eq!(min, 16);
                }
                _ => panic!("Expected InputTooSmall error"),
            }
        }

        #[test]
        fn test_validate_input_size_too_large_fails() {
            let input = vec![0u8; 128];
            let result = validate_input_size(&input, 16, 64);
            assert!(result.is_err());
            match result.unwrap_err() {
                ValidationError::InputTooLarge(actual, max) => {
                    assert_eq!(actual, 128);
                    assert_eq!(max, 64);
                }
                _ => panic!("Expected InputTooLarge error"),
            }
        }

        #[test]
        fn test_validate_input_size_empty_input_passes_validation() {
            let input = vec![];
            assert!(validate_input_size(&input, 0, 64).is_ok());
            assert!(validate_input_size(&input, 1, 64).is_err());
        }

        #[test]
        fn test_validate_input_size_zero_max_passes_validation() {
            let input = vec![];
            assert!(validate_input_size(&input, 0, 0).is_ok());
        }

        #[test]
        fn test_validation_error_display_passes_validation() {
            let err = ValidationError::InputTooSmall(10, 20);
            let msg = format!("{err}");
            assert!(msg.contains("10"));
            assert!(msg.contains("20"));
        }

        #[test]
        fn test_validation_error_debug_passes_validation() {
            let err = ValidationError::InputTooLarge(100, 50);
            let debug = format!("{:?}", err);
            assert!(debug.contains("InputTooLarge"));
        }
    }

    // ============================================================================
    // Bounds Validation Tests
    // ============================================================================

    mod bounds_validation_tests {
        use super::*;

        #[test]
        fn test_validate_bounds_valid_passes_validation() {
            assert!(validate_bounds(50, 0, 100).is_ok());
        }

        #[test]
        fn test_validate_bounds_exact_min_passes_validation() {
            assert!(validate_bounds(0, 0, 100).is_ok());
        }

        #[test]
        fn test_validate_bounds_exact_max_passes_validation() {
            assert!(validate_bounds(100, 0, 100).is_ok());
        }

        #[test]
        fn test_validate_bounds_too_small_fails() {
            let result = validate_bounds(5, 10, 100);
            assert!(result.is_err());
            match result.unwrap_err() {
                BoundsError::ValueTooSmall(value, min) => {
                    assert_eq!(value, 5);
                    assert_eq!(min, 10);
                }
                _ => panic!("Expected ValueTooSmall error"),
            }
        }

        #[test]
        fn test_validate_bounds_too_large_fails() {
            let result = validate_bounds(150, 10, 100);
            assert!(result.is_err());
            match result.unwrap_err() {
                BoundsError::ValueTooLarge(value, max) => {
                    assert_eq!(value, 150);
                    assert_eq!(max, 100);
                }
                _ => panic!("Expected ValueTooLarge error"),
            }
        }

        #[test]
        fn test_validate_bounds_equal_min_max_passes_validation() {
            assert!(validate_bounds(42, 42, 42).is_ok());
            assert!(validate_bounds(41, 42, 42).is_err());
            assert!(validate_bounds(43, 42, 42).is_err());
        }

        #[test]
        fn test_bounds_error_display_passes_validation() {
            let err = BoundsError::ValueTooSmall(5, 10);
            let msg = format!("{err}");
            assert!(msg.contains("5"));
            assert!(msg.contains("10"));
        }
    }

    // ============================================================================
    // Format Validation Tests
    // ============================================================================

    mod format_validation_tests {
        use super::*;

        #[test]
        fn test_validate_key_format_valid_passes_validation() {
            let key = vec![0u8; 32];
            assert!(validate_key_format(&key, 32).is_ok());
        }

        #[test]
        fn test_validate_key_format_invalid_size_fails() {
            let key = vec![0u8; 24];
            let result = validate_key_format(&key, 32);
            assert!(result.is_err());
            match result.unwrap_err() {
                FormatError::InvalidKeySize(actual, expected) => {
                    assert_eq!(actual, 24);
                    assert_eq!(expected, 32);
                }
            }
        }

        #[test]
        fn test_validate_key_format_aes_128_passes_validation() {
            let key = vec![0u8; 16];
            assert!(validate_key_format(&key, 16).is_ok());
        }

        #[test]
        fn test_validate_key_format_aes_256_passes_validation() {
            let key = vec![0u8; 32];
            assert!(validate_key_format(&key, 32).is_ok());
        }

        #[test]
        fn test_validate_key_format_empty_passes_validation() {
            let key = vec![];
            assert!(validate_key_format(&key, 0).is_ok());
            assert!(validate_key_format(&key, 1).is_err());
        }

        #[test]
        fn test_format_error_display_passes_validation() {
            let err = FormatError::InvalidKeySize(16, 32);
            let msg = format!("{err}");
            assert!(msg.contains("16"));
            assert!(msg.contains("32"));
        }
    }

    // ============================================================================
    // Resource Limits Tests
    // ============================================================================

    mod resource_limits_tests {
        use super::*;

        #[test]
        fn test_resource_limits_default_passes_validation() {
            let limits = ResourceLimits::default();
            assert_eq!(limits.max_encryption_size_bytes, 100 * 1024 * 1024);
            assert_eq!(limits.max_signature_size_bytes, 64 * 1024);
            assert_eq!(limits.max_decryption_size_bytes, 100 * 1024 * 1024);
        }

        #[test]
        fn test_resource_limits_new_passes_validation() {
            let limits = ResourceLimits::new(50 * 1024 * 1024, 32 * 1024, 50 * 1024 * 1024);
            assert_eq!(limits.max_encryption_size_bytes, 50 * 1024 * 1024);
            assert_eq!(limits.max_signature_size_bytes, 32 * 1024);
            assert_eq!(limits.max_decryption_size_bytes, 50 * 1024 * 1024);
        }

        #[test]
        fn test_validate_encryption_size_valid_passes_validation() {
            assert!(validate_encryption_size(1024 * 1024).is_ok());
        }

        #[test]
        fn test_validate_encryption_size_exceeded_has_correct_size() {
            let result = validate_encryption_size(200 * 1024 * 1024);
            assert!(result.is_err());
            match result.unwrap_err() {
                ResourceError::EncryptionSizeLimitExceeded { requested, limit } => {
                    assert_eq!(requested, 200 * 1024 * 1024);
                    assert_eq!(limit, 100 * 1024 * 1024);
                }
                _ => panic!("Expected EncryptionSizeLimitExceeded error"),
            }
        }

        #[test]
        fn test_validate_signature_size_valid_passes_validation() {
            assert!(validate_signature_size(1024).is_ok());
        }

        #[test]
        fn test_validate_signature_size_exceeded_has_correct_size() {
            let result = validate_signature_size(100 * 1024);
            assert!(result.is_err());
            match result.unwrap_err() {
                ResourceError::SignatureSizeLimitExceeded { requested, limit } => {
                    assert_eq!(requested, 100 * 1024);
                    assert_eq!(limit, 64 * 1024);
                }
                _ => panic!("Expected SignatureSizeLimitExceeded error"),
            }
        }

        #[test]
        fn test_validate_decryption_size_valid_passes_validation() {
            assert!(validate_decryption_size(1024 * 1024).is_ok());
        }

        #[test]
        fn test_validate_decryption_size_exceeded_has_correct_size() {
            let result = validate_decryption_size(200 * 1024 * 1024);
            assert!(result.is_err());
            match result.unwrap_err() {
                ResourceError::DecryptionSizeLimitExceeded { requested, limit } => {
                    assert_eq!(requested, 200 * 1024 * 1024);
                    assert_eq!(limit, 100 * 1024 * 1024);
                }
                _ => panic!("Expected DecryptionSizeLimitExceeded error"),
            }
        }
    }

    // ============================================================================
    // Resource Limits Manager Tests
    // ============================================================================

    mod resource_limits_manager_tests {
        use super::*;

        #[test]
        fn test_resource_limits_manager_new_passes_validation() {
            let manager = ResourceLimitsManager::new();
            let limits = manager.get_limits().unwrap();
            assert_eq!(limits.max_encryption_size_bytes, 100 * 1024 * 1024);
        }

        #[test]
        fn test_resource_limits_manager_with_limits_passes_validation() {
            let custom_limits = ResourceLimits::new(25 * 1024 * 1024, 16 * 1024, 25 * 1024 * 1024);
            let manager = ResourceLimitsManager::with_limits(custom_limits);
            let limits = manager.get_limits().unwrap();
            assert_eq!(limits.max_encryption_size_bytes, 25 * 1024 * 1024);
        }

        #[test]
        fn test_resource_limits_manager_update_passes_validation() {
            let manager = ResourceLimitsManager::new();
            let new_limits = ResourceLimits::new(10 * 1024 * 1024, 8 * 1024, 10 * 1024 * 1024);
            manager.update_limits(new_limits).unwrap();
            let limits = manager.get_limits().unwrap();
            assert_eq!(limits.max_encryption_size_bytes, 10 * 1024 * 1024);
        }

        #[test]
        fn test_resource_limits_manager_validate_encryption_passes_validation() {
            let manager = ResourceLimitsManager::new();
            assert!(manager.validate_encryption_size(1024 * 1024).is_ok());
            assert!(manager.validate_encryption_size(200 * 1024 * 1024).is_err());
        }

        #[test]
        fn test_resource_limits_manager_validate_signature_passes_validation() {
            let manager = ResourceLimitsManager::new();
            assert!(manager.validate_signature_size(1024).is_ok());
            assert!(manager.validate_signature_size(100 * 1024).is_err());
        }

        #[test]
        fn test_resource_limits_manager_validate_decryption_passes_validation() {
            let manager = ResourceLimitsManager::new();
            assert!(manager.validate_decryption_size(1024 * 1024).is_ok());
            assert!(manager.validate_decryption_size(200 * 1024 * 1024).is_err());
        }

        #[test]
        fn test_resource_limits_manager_default_passes_validation() {
            let manager = ResourceLimitsManager::default();
            let limits = manager.get_limits().unwrap();
            assert_eq!(limits.max_encryption_size_bytes, 100 * 1024 * 1024);
        }
    }

    // ============================================================================
    // Global Resource Limits Tests
    // ============================================================================

    mod global_resource_limits_tests {
        use super::*;

        #[test]
        fn test_get_global_resource_limits_passes_validation() {
            let manager = get_global_resource_limits();
            let limits = manager.get_limits().unwrap();
            assert!(limits.max_encryption_size_bytes > 0);
        }

        #[test]
        fn test_global_validate_encryption_size_passes_validation() {
            assert!(validate_encryption_size(1024 * 1024).is_ok());
        }

        #[test]
        fn test_global_validate_signature_size_passes_validation() {
            assert!(validate_signature_size(1024).is_ok());
        }

        #[test]
        fn test_global_validate_decryption_size_passes_validation() {
            assert!(validate_decryption_size(1024 * 1024).is_ok());
        }
    }

    // ============================================================================
    // Resource Error Tests
    // ============================================================================

    mod resource_error_tests {
        use super::*;

        #[test]
        fn test_resource_error_key_derivation_display_passes_validation() {
            let err = ResourceError::KeyDerivationLimitExceeded { requested: 2000, limit: 1000 };
            let msg = format!("{err}");
            assert!(msg.contains("2000"));
            assert!(msg.contains("1000"));
            assert!(msg.contains("Key derivation"));
        }

        #[test]
        fn test_resource_error_encryption_display_passes_validation() {
            let err = ResourceError::EncryptionSizeLimitExceeded {
                requested: 200 * 1024 * 1024,
                limit: 100 * 1024 * 1024,
            };
            let msg = format!("{err}");
            assert!(msg.contains("Encryption"));
        }

        #[test]
        fn test_resource_error_signature_display_passes_validation() {
            let err = ResourceError::SignatureSizeLimitExceeded {
                requested: 100 * 1024,
                limit: 64 * 1024,
            };
            let msg = format!("{err}");
            assert!(msg.contains("Signature"));
        }

        #[test]
        fn test_resource_error_decryption_display_passes_validation() {
            let err = ResourceError::DecryptionSizeLimitExceeded {
                requested: 200 * 1024 * 1024,
                limit: 100 * 1024 * 1024,
            };
            let msg = format!("{err}");
            assert!(msg.contains("Decryption"));
        }

        #[test]
        fn test_resource_error_debug_passes_validation() {
            let err = ResourceError::KeyDerivationLimitExceeded { requested: 2000, limit: 1000 };
            let debug = format!("{:?}", err);
            assert!(debug.contains("KeyDerivationLimitExceeded"));
        }
    }

    // ============================================================================
    // Edge Case Tests
    // ============================================================================

    mod edge_case_tests {
        use super::*;

        #[test]
        fn test_zero_values_passes_validation() {
            // Zero-length input
            let empty = vec![];
            assert!(validate_input_size(&empty, 0, 0).is_ok());

            // Zero bounds
            assert!(validate_bounds(0, 0, 0).is_ok());

            // Zero key size
            assert!(validate_key_format(&[], 0).is_ok());
        }

        #[test]
        fn test_max_values_passes_validation() {
            // Large values within limits
            assert!(validate_bounds(usize::MAX - 1, 0, usize::MAX).is_ok());
        }

        #[test]
        fn test_boundary_conditions_passes_validation() {
            // Exact boundary tests
            let input = vec![0u8; 100];
            assert!(validate_input_size(&input, 100, 100).is_ok());
            assert!(validate_input_size(&input, 101, 200).is_err());
            assert!(validate_input_size(&input, 0, 99).is_err());
        }
    }

    // ============================================================================
    // Concurrent Access Tests
    // ============================================================================

    mod concurrent_tests {
        use super::*;
        use std::sync::Arc;
        use std::thread;

        #[test]
        fn test_resource_limits_manager_concurrent_read_succeeds() {
            let manager = Arc::new(ResourceLimitsManager::new());
            let mut handles = vec![];

            for _ in 0..10 {
                let manager_clone = Arc::clone(&manager);
                handles.push(thread::spawn(move || {
                    for _ in 0..100 {
                        let limits = manager_clone.get_limits().unwrap();
                        assert!(limits.max_encryption_size_bytes > 0);
                    }
                }));
            }

            for handle in handles {
                handle.join().unwrap();
            }
        }

        #[test]
        fn test_resource_limits_manager_concurrent_validation_succeeds() {
            let manager = Arc::new(ResourceLimitsManager::new());
            let mut handles = vec![];

            for _ in 0..10 {
                let manager_clone = Arc::clone(&manager);
                handles.push(thread::spawn(move || {
                    for i in 0..100 {
                        let _ = manager_clone.validate_encryption_size(i * 1024);
                        let _ = manager_clone.validate_signature_size(i * 10);
                    }
                }));
            }

            for handle in handles {
                handle.join().unwrap();
            }
        }
    }

    // ============================================================================
    // Property-Based Tests
    // ============================================================================

    mod property_tests {
        use super::*;

        #[test]
        fn test_input_validation_symmetry_passes_validation() {
            // If min == max, only exact size is valid
            for size in [16, 32, 64, 128] {
                let input = vec![0u8; size];
                assert!(validate_input_size(&input, size, size).is_ok());

                let smaller = vec![0u8; size - 1];
                assert!(validate_input_size(&smaller, size, size).is_err());

                let larger = vec![0u8; size + 1];
                assert!(validate_input_size(&larger, size, size).is_err());
            }
        }

        #[test]
        fn test_bounds_validation_ordering_passes_validation() {
            // Values within bounds are always valid
            for (min, max) in [(0, 100), (10, 50), (100, 1000)] {
                for value in (min..=max).step_by(std::cmp::max(1, (max - min) / 10)) {
                    assert!(validate_bounds(value, min, max).is_ok());
                }
            }
        }

        #[test]
        fn test_key_format_sizes_passes_validation() {
            // Common cryptographic key sizes
            for size in [16, 24, 32, 48, 64] {
                let key = vec![0u8; size];
                assert!(validate_key_format(&key, size).is_ok());
                assert!(validate_key_format(&key, size + 1).is_err());
                if size > 0 {
                    assert!(validate_key_format(&key, size - 1).is_err());
                }
            }
        }
    }

    // ============================================================================
    // Integration Tests
    // ============================================================================

    mod integration_tests {
        use super::*;

        #[test]
        fn test_combined_validation_workflow_passes_validation() {
            // Simulate a typical cryptographic operation validation workflow

            // 1. Validate input data size
            let plaintext = vec![0u8; 1024];
            assert!(validate_input_size(&plaintext, 1, 10 * 1024 * 1024).is_ok());

            // 2. Validate key format
            let key = vec![0u8; 32];
            assert!(validate_key_format(&key, 32).is_ok());

            // 3. Validate resource limits
            assert!(validate_encryption_size(plaintext.len()).is_ok());

            // 4. Validate output bounds
            let expected_output_size = plaintext.len() + 16; // Add authentication tag
            assert!(validate_bounds(expected_output_size, 0, 100 * 1024 * 1024).is_ok());
        }

        #[test]
        fn test_signature_validation_workflow_passes_validation() {
            // Validate signature operation
            let message = vec![0u8; 512];
            let signature_key = vec![0u8; 32];

            // Validate inputs
            assert!(validate_input_size(&message, 0, 1024 * 1024).is_ok());
            assert!(validate_key_format(&signature_key, 32).is_ok());

            // Validate signature size limit
            let signature_size = 64;
            assert!(validate_signature_size(signature_size).is_ok());
        }

        #[test]
        fn test_custom_limits_manager_passes_validation() {
            // Create manager with restricted limits
            let restricted_limits = ResourceLimits::new(
                1024 * 1024, // max 1MB encryption
                4096,        // max 4KB signatures
                1024 * 1024, // max 1MB decryption
            );
            let manager = ResourceLimitsManager::with_limits(restricted_limits);

            // These should fail with restricted limits
            assert!(manager.validate_encryption_size(2 * 1024 * 1024).is_err());
            assert!(manager.validate_signature_size(8192).is_err());
            assert!(manager.validate_decryption_size(2 * 1024 * 1024).is_err());

            // These should pass
            assert!(manager.validate_encryption_size(512 * 1024).is_ok());
            assert!(manager.validate_signature_size(2048).is_ok());
            assert!(manager.validate_decryption_size(512 * 1024).is_ok());
        }
    }

    // ============================================================================
    // Output Validation Tests
    // ============================================================================

    mod output_validation_tests {
        use super::*;

        #[test]
        fn test_simple_validator_new_succeeds() {
            let validator = SimpleValidator::new();
            let output = vec![0u8; 32];
            assert!(validator.validate_output(&output).is_ok());
        }

        #[test]
        fn test_simple_validator_default_succeeds() {
            let validator = SimpleValidator::default();
            let output = vec![0u8; 32];
            assert!(validator.validate_output(&output).is_ok());
        }

        #[test]
        fn test_output_validator_empty_succeeds() {
            let validator = SimpleValidator::new();
            let output = vec![];
            let result = validator.validate_output(&output);
            assert!(result.is_err());
            assert!(matches!(result.unwrap_err(), OutputError::EmptyOutput));
        }

        #[test]
        fn test_output_validator_too_large_fails() {
            let validator = SimpleValidator::new();
            // Create output larger than 10MB limit
            let output = vec![0u8; 11 * 1024 * 1024];
            let result = validator.validate_output(&output);
            assert!(result.is_err());
            match result.unwrap_err() {
                OutputError::OutputTooLarge { size, max } => {
                    assert_eq!(size, 11 * 1024 * 1024);
                    assert_eq!(max, 10 * 1024 * 1024);
                }
                _ => panic!("Expected OutputTooLarge error"),
            }
        }

        #[test]
        fn test_output_validator_invalid_byte_fails() {
            let validator = SimpleValidator::new();
            // 0xFF is considered invalid in SimpleValidator
            let output = vec![0u8, 0x10, 0xFF, 0x20];
            let result = validator.validate_output(&output);
            assert!(result.is_err());
            match result.unwrap_err() {
                OutputError::InvalidByte { position, byte } => {
                    assert_eq!(position, 2);
                    assert_eq!(byte, 0xFF);
                }
                _ => panic!("Expected InvalidByte error"),
            }
        }

        #[test]
        fn test_bounds_checker_valid_passes_validation() {
            let validator = SimpleValidator::new();
            let value = vec![0u8; 32];
            assert!(validator.check_bounds(&value, 16, 64).is_ok());
        }

        #[test]
        fn test_bounds_checker_exact_min_passes_validation() {
            let validator = SimpleValidator::new();
            let value = vec![0u8; 16];
            assert!(validator.check_bounds(&value, 16, 64).is_ok());
        }

        #[test]
        fn test_bounds_checker_exact_max_passes_validation() {
            let validator = SimpleValidator::new();
            let value = vec![0u8; 64];
            assert!(validator.check_bounds(&value, 16, 64).is_ok());
        }

        #[test]
        fn test_bounds_checker_out_of_bounds_fails() {
            let validator = SimpleValidator::new();
            let value = vec![0u8; 8];
            let result = validator.check_bounds(&value, 16, 64);
            assert!(result.is_err());
            match result.unwrap_err() {
                OutputBoundsError::OutOfBounds { actual, min, max } => {
                    assert_eq!(actual, 8);
                    assert_eq!(min, 16);
                    assert_eq!(max, 64);
                }
                _ => panic!("Expected OutOfBounds error"),
            }
        }

        #[test]
        fn test_bounds_checker_invalid_bounds_fails() {
            let validator = SimpleValidator::new();
            let value = vec![0u8; 32];
            // min > max is invalid
            let result = validator.check_bounds(&value, 100, 50);
            assert!(result.is_err());
            match result.unwrap_err() {
                OutputBoundsError::InvalidBounds { min, max } => {
                    assert_eq!(min, 100);
                    assert_eq!(max, 50);
                }
                _ => panic!("Expected InvalidBounds error"),
            }
        }

        #[test]
        fn test_output_error_display_passes_validation() {
            let err = OutputError::EmptyOutput;
            let msg = format!("{err}");
            assert!(msg.contains("empty"));

            let err = OutputError::InvalidLength("test".to_string());
            let msg = format!("{err}");
            assert!(msg.contains("Invalid"));

            let err = OutputError::InvalidByte { position: 5, byte: 0xAB };
            let msg = format!("{err}");
            assert!(msg.contains("5"));
            assert!(msg.contains("ab") || msg.contains("AB"));

            let err = OutputError::OutputTooLarge { size: 100, max: 50 };
            let msg = format!("{err}");
            assert!(msg.contains("100"));
            assert!(msg.contains("50"));
        }

        #[test]
        fn test_output_bounds_error_display_passes_validation() {
            let err = OutputBoundsError::OutOfBounds { actual: 10, min: 20, max: 30 };
            let msg = format!("{err}");
            assert!(msg.contains("10"));
            assert!(msg.contains("20"));
            assert!(msg.contains("30"));

            let err = OutputBoundsError::InvalidBounds { min: 100, max: 50 };
            let msg = format!("{err}");
            assert!(msg.contains("100"));
            assert!(msg.contains("50"));
        }
    }
}
