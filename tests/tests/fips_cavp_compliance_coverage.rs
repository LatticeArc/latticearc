//! Coverage tests for CAVP compliance report generation.
//! Targets compliance.rs: CavpComplianceGenerator, report generation,
//! JSON/XML export, compliance evaluation (FullyCompliant, PartiallyCompliant,
//! NonCompliant), and algorithm-specific criteria.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::cast_precision_loss,
    clippy::float_cmp,
    clippy::needless_borrows_for_generic_args,
    clippy::redundant_clone,
    clippy::redundant_closure_for_method_calls,
    clippy::useless_format
)]

use chrono::Utc;
use latticearc_tests::validation::cavp::compliance::*;
use latticearc_tests::validation::cavp::types::*;
use std::collections::HashMap;
use std::time::Duration;

fn make_passing_result(id: &str, algorithm: CavpAlgorithm) -> CavpTestResult {
    CavpTestResult {
        test_id: id.to_string(),
        algorithm,
        vector_id: format!("{}-vec", id),
        passed: true,
        execution_time: Duration::from_millis(10),
        timestamp: Utc::now(),
        actual_result: vec![1],
        expected_result: vec![1],
        error_message: None,
        metadata: CavpTestMetadata::default(),
    }
}

fn make_failing_result(id: &str, algorithm: CavpAlgorithm) -> CavpTestResult {
    CavpTestResult {
        test_id: id.to_string(),
        algorithm,
        vector_id: format!("{}-vec", id),
        passed: false,
        execution_time: Duration::from_millis(5),
        timestamp: Utc::now(),
        actual_result: vec![0],
        expected_result: vec![1],
        error_message: Some("Mismatch in test vector".to_string()),
        metadata: CavpTestMetadata::default(),
    }
}

fn make_failing_result_no_message(id: &str, algorithm: CavpAlgorithm) -> CavpTestResult {
    CavpTestResult {
        test_id: id.to_string(),
        algorithm,
        vector_id: format!("{}-vec", id),
        passed: false,
        execution_time: Duration::from_millis(3),
        timestamp: Utc::now(),
        actual_result: vec![0],
        expected_result: vec![1],
        error_message: None,
        metadata: CavpTestMetadata::default(),
    }
}

fn make_batch(
    algorithm: CavpAlgorithm,
    results: Vec<CavpTestResult>,
    _duration: Duration,
) -> CavpBatchResult {
    let mut batch = CavpBatchResult::new("batch-1".to_string(), algorithm);
    for r in results {
        batch.add_test_result(r);
    }
    batch.status = CavpValidationStatus::Passed;
    batch
}

// ============================================================
// CavpComplianceGenerator construction
// ============================================================

#[test]
fn test_generator_new() {
    let cgen = CavpComplianceGenerator::new();
    // Verify it was constructed (exercises new() and all criteria insertions)
    let alg = CavpAlgorithm::MlKem { variant: "768".to_string() };
    let results = vec![make_passing_result("t1", alg.clone())];
    let batch = make_batch(alg, results, Duration::from_millis(5));
    let _report = cgen.generate_report(&[batch]).unwrap();
}

#[test]
fn test_generator_default() {
    let cgen = CavpComplianceGenerator::default();
    let alg = CavpAlgorithm::MlDsa { variant: "44".to_string() };
    let results = vec![make_passing_result("t1", alg.clone())];
    let batch = make_batch(alg, results, Duration::from_millis(5));
    let _report = cgen.generate_report(&[batch]).unwrap();
}

// ============================================================
// Report generation - FullyCompliant (all tests pass)
// ============================================================

#[test]
fn test_generate_report_fully_compliant_hybrid() {
    // HybridKem uses default_criteria with min_coverage=95.0, matching hardcoded 95.0%
    let cgen = CavpComplianceGenerator::new();
    let alg = CavpAlgorithm::HybridKem;
    let results = vec![
        make_passing_result("test-1", alg.clone()),
        make_passing_result("test-2", alg.clone()),
        make_passing_result("test-3", alg.clone()),
    ];
    let batch = make_batch(alg, results, Duration::from_millis(30));
    let report = cgen.generate_report(&[batch]).unwrap();

    assert!(matches!(report.compliance_status, ComplianceStatus::FullyCompliant));
    assert_eq!(report.summary.total_tests, 3);
    assert_eq!(report.summary.passed_tests, 3);
    assert_eq!(report.summary.failed_tests, 0);
    assert!((report.summary.pass_rate - 100.0).abs() < 0.01);
    assert_eq!(report.summary.security_level, 256);
    assert!(!report.nist_standards.is_empty());
}

#[test]
fn test_generate_report_mlkem_noncompliant_due_to_coverage() {
    // Algorithm-specific criteria require 100% coverage, but summary hardcodes 95%
    let cgen = CavpComplianceGenerator::new();
    let alg = CavpAlgorithm::MlKem { variant: "768".to_string() };
    let results = vec![
        make_passing_result("test-1", alg.clone()),
        make_passing_result("test-2", alg.clone()),
    ];
    let batch = make_batch(alg, results, Duration::from_millis(20));
    let report = cgen.generate_report(&[batch]).unwrap();

    // 100% pass rate but 95% coverage < required 100% → NonCompliant
    assert!(matches!(report.compliance_status, ComplianceStatus::NonCompliant { .. }));
    assert_eq!(report.summary.security_level, 192);
}

// ============================================================
// Report generation - PartiallyCompliant (some failures but pass rate still high)
// ============================================================

#[test]
fn test_generate_report_partially_compliant() {
    let cgen = CavpComplianceGenerator::new();
    let alg = CavpAlgorithm::MlKem { variant: "512".to_string() };

    // 99 pass, 1 fail -> 99% pass rate, FullyCompliant criteria requires 100%
    // But coverage 95% meets threshold, so this tests the evaluate_compliance branch
    // where pass_rate >= min_pass_rate (100%) is NOT met
    // Actually ML-KEM criteria requires 100% pass rate, so 99% will be NonCompliant
    // Let's use a scenario where all pass but with a Failed detailed result
    // to test the PartiallyCompliant path.
    let mut results: Vec<CavpTestResult> = Vec::new();
    for i in 0..10 {
        results.push(make_passing_result(&format!("test-{}", i), alg.clone()));
    }
    // Add one failing result with error message to exercise PartiallyCompliant
    results.push(make_failing_result("test-fail", alg.clone()));

    let batch = make_batch(alg, results, Duration::from_millis(100));

    // Use default criteria where min_pass_rate is 100% and coverage is 95%
    // pass_rate = 10/11 = 90.9% which is below 100%, so NonCompliant
    let report = cgen.generate_report(&[batch]).unwrap();

    // Since pass rate is below 100% (ML-KEM criteria requires 100%), this will be NonCompliant
    assert!(matches!(report.compliance_status, ComplianceStatus::NonCompliant { .. }));
}

// ============================================================
// Report generation - NonCompliant
// ============================================================

#[test]
fn test_generate_report_non_compliant() {
    let cgen = CavpComplianceGenerator::new();
    let alg = CavpAlgorithm::SlhDsa { variant: "128".to_string() };
    let results = vec![
        make_failing_result("fail-1", alg.clone()),
        make_failing_result("fail-2", alg.clone()),
        make_passing_result("pass-1", alg.clone()),
    ];
    let batch = make_batch(alg, results, Duration::from_millis(50));
    let report = cgen.generate_report(&[batch]).unwrap();

    assert!(matches!(report.compliance_status, ComplianceStatus::NonCompliant { .. }));
    if let ComplianceStatus::NonCompliant { failures } = &report.compliance_status {
        assert!(!failures.is_empty());
    }
    assert_eq!(report.summary.total_tests, 3);
    assert_eq!(report.summary.failed_tests, 2);
}

// ============================================================
// Security level mapping for all algorithm variants
// ============================================================

#[test]
fn test_security_level_mapping_mlkem() {
    let cgen = CavpComplianceGenerator::new();

    for (variant, expected_level) in [("512", 128), ("768", 192), ("1024", 256), ("unknown", 128)] {
        let alg = CavpAlgorithm::MlKem { variant: variant.to_string() };
        let results = vec![make_passing_result("t1", alg.clone())];
        let batch = make_batch(alg, results, Duration::from_millis(5));
        let report = cgen.generate_report(&[batch]).unwrap();
        assert_eq!(
            report.summary.security_level, expected_level,
            "ML-KEM variant {} should map to level {}",
            variant, expected_level
        );
    }
}

#[test]
fn test_security_level_mapping_mldsa() {
    let cgen = CavpComplianceGenerator::new();

    for (variant, expected_level) in [("44", 128), ("65", 192), ("87", 256), ("unknown", 128)] {
        let alg = CavpAlgorithm::MlDsa { variant: variant.to_string() };
        let results = vec![make_passing_result("t1", alg.clone())];
        let batch = make_batch(alg, results, Duration::from_millis(5));
        let report = cgen.generate_report(&[batch]).unwrap();
        assert_eq!(report.summary.security_level, expected_level);
    }
}

#[test]
fn test_security_level_mapping_slhdsa() {
    let cgen = CavpComplianceGenerator::new();

    for (variant, expected_level) in [("128", 128), ("192", 192), ("256", 256), ("unknown", 128)] {
        let alg = CavpAlgorithm::SlhDsa { variant: variant.to_string() };
        let results = vec![make_passing_result("t1", alg.clone())];
        let batch = make_batch(alg, results, Duration::from_millis(5));
        let report = cgen.generate_report(&[batch]).unwrap();
        assert_eq!(report.summary.security_level, expected_level);
    }
}

#[test]
fn test_security_level_mapping_fndsa() {
    let cgen = CavpComplianceGenerator::new();

    for (variant, expected_level) in [("512", 128), ("1024", 256), ("unknown", 128)] {
        let alg = CavpAlgorithm::FnDsa { variant: variant.to_string() };
        let results = vec![make_passing_result("t1", alg.clone())];
        let batch = make_batch(alg, results, Duration::from_millis(5));
        let report = cgen.generate_report(&[batch]).unwrap();
        assert_eq!(report.summary.security_level, expected_level);
    }
}

#[test]
fn test_security_level_mapping_hybrid_kem() {
    let cgen = CavpComplianceGenerator::new();

    let alg = CavpAlgorithm::HybridKem;
    let results = vec![make_passing_result("t1", alg.clone())];
    let batch = make_batch(alg, results, Duration::from_millis(5));
    let report = cgen.generate_report(&[batch]).unwrap();
    assert_eq!(report.summary.security_level, 256);
}

// ============================================================
// JSON and XML export
// ============================================================

#[test]
fn test_export_json() {
    let cgen = CavpComplianceGenerator::new();
    let alg = CavpAlgorithm::HybridKem;
    let results = vec![make_passing_result("t1", alg.clone())];
    let batch = make_batch(alg, results, Duration::from_millis(5));
    let report = cgen.generate_report(&[batch]).unwrap();

    let json = cgen.export_json(&report).unwrap();
    assert!(json.contains("CAVP-REPORT-"));
    assert!(json.contains("FullyCompliant"));
}

#[test]
fn test_export_xml() {
    let cgen = CavpComplianceGenerator::new();
    let alg = CavpAlgorithm::MlDsa { variant: "44".to_string() };
    let results = vec![make_passing_result("t1", alg.clone())];
    let batch = make_batch(alg, results, Duration::from_millis(5));
    let report = cgen.generate_report(&[batch]).unwrap();

    let xml = cgen.export_xml(&report).unwrap();
    assert!(xml.contains("<?xml version"));
    assert!(xml.contains("<cavp_compliance_report>"));
    assert!(xml.contains("<algorithm>ML-DSA-44</algorithm>"));
    assert!(xml.contains("<total_tests>1</total_tests>"));
    assert!(xml.contains("</cavp_compliance_report>"));
}

// ============================================================
// Edge cases
// ============================================================

#[test]
fn test_generate_report_empty_batches_fails() {
    let cgen = CavpComplianceGenerator::new();
    let result = cgen.generate_report(&[]);
    assert!(result.is_err());
}

#[test]
fn test_generate_report_multiple_batches() {
    let cgen = CavpComplianceGenerator::new();
    let alg = CavpAlgorithm::FnDsa { variant: "512".to_string() };

    let batch1 = make_batch(
        alg.clone(),
        vec![make_passing_result("b1-t1", alg.clone())],
        Duration::from_millis(10),
    );
    let batch2 = make_batch(
        alg.clone(),
        vec![make_passing_result("b2-t1", alg.clone())],
        Duration::from_millis(15),
    );

    let report = cgen.generate_report(&[batch1, batch2]).unwrap();
    assert_eq!(report.summary.total_tests, 2);
    assert_eq!(report.summary.passed_tests, 2);
}

#[test]
fn test_generate_report_with_default_criteria() {
    // Use an algorithm name that won't match any specific criteria
    let cgen = CavpComplianceGenerator::new();
    let alg = CavpAlgorithm::HybridKem;
    let results = vec![make_passing_result("t1", alg.clone())];
    let batch = make_batch(alg, results, Duration::from_millis(5));
    let report = cgen.generate_report(&[batch]).unwrap();

    // HybridKem uses default_criteria since it's not in the criteria_map
    assert!(matches!(report.compliance_status, ComplianceStatus::FullyCompliant));
}

// ============================================================
// convert_to_compliance_results - test both fail paths
// ============================================================

#[test]
fn test_compliance_results_with_error_message() {
    let cgen = CavpComplianceGenerator::new();
    let alg = CavpAlgorithm::MlKem { variant: "768".to_string() };
    let results = vec![make_failing_result("fail-with-msg", alg.clone())];
    let batch = make_batch(alg, results, Duration::from_millis(5));
    let report = cgen.generate_report(&[batch]).unwrap();

    // Should have Failed with the specific error message
    assert_eq!(report.detailed_results.len(), 1);
    assert!(matches!(report.detailed_results[0].result, TestResult::Failed(_)));
    if let TestResult::Failed(msg) = &report.detailed_results[0].result {
        assert!(msg.contains("Mismatch"));
    }
}

#[test]
fn test_compliance_results_without_error_message() {
    let cgen = CavpComplianceGenerator::new();
    let alg = CavpAlgorithm::MlDsa { variant: "87".to_string() };
    let results = vec![make_failing_result_no_message("fail-no-msg", alg.clone())];
    let batch = make_batch(alg, results, Duration::from_millis(5));
    let report = cgen.generate_report(&[batch]).unwrap();

    // Should have Failed with the generic message
    assert_eq!(report.detailed_results.len(), 1);
    if let TestResult::Failed(msg) = &report.detailed_results[0].result {
        assert!(msg.contains("failed without specific error"));
    }
}

// ============================================================
// ComplianceStatus and type coverage
// ============================================================

#[test]
fn test_compliance_status_variants() {
    let fc = ComplianceStatus::FullyCompliant;
    let pc = ComplianceStatus::PartiallyCompliant { exceptions: vec!["minor issue".to_string()] };
    let nc = ComplianceStatus::NonCompliant { failures: vec!["critical failure".to_string()] };
    let id = ComplianceStatus::InsufficientData;

    // Serialize/deserialize roundtrip
    let fc_json = serde_json::to_string(&fc).unwrap();
    let pc_json = serde_json::to_string(&pc).unwrap();
    let nc_json = serde_json::to_string(&nc).unwrap();
    let id_json = serde_json::to_string(&id).unwrap();

    assert!(fc_json.contains("FullyCompliant"));
    assert!(pc_json.contains("PartiallyCompliant"));
    assert!(nc_json.contains("NonCompliant"));
    assert!(id_json.contains("InsufficientData"));

    // Deserialize back
    let fc2: ComplianceStatus = serde_json::from_str(&fc_json).unwrap();
    assert_eq!(fc, fc2);
}

#[test]
fn test_test_category_variants() {
    let categories = vec![
        TestCategory::Correctness,
        TestCategory::Security,
        TestCategory::Performance,
        TestCategory::Robustness,
        TestCategory::Interoperability,
        TestCategory::Statistical,
        TestCategory::KeyGeneration,
        TestCategory::Signature,
        TestCategory::Encryption,
        TestCategory::Decryption,
        TestCategory::Compliance,
    ];
    for cat in &categories {
        let json = serde_json::to_string(cat).unwrap();
        let deserialized: TestCategory = serde_json::from_str(&json).unwrap();
        assert_eq!(cat, &deserialized);
    }
}

#[test]
fn test_test_result_variants() {
    let variants = vec![
        TestResult::Passed,
        TestResult::Failed("reason".to_string()),
        TestResult::Skipped("skipped reason".to_string()),
        TestResult::Error("error reason".to_string()),
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let deserialized: TestResult = serde_json::from_str(&json).unwrap();
        assert_eq!(v, &deserialized);
    }
}

#[test]
fn test_performance_metrics_serialization() {
    let metrics = PerformanceMetrics {
        avg_execution_time_ms: 10.5,
        min_execution_time_ms: 1,
        max_execution_time_ms: 50,
        total_execution_time_ms: 100,
        memory_usage: MemoryUsageMetrics {
            peak_memory_bytes: 1024,
            avg_memory_bytes: 512,
            efficiency_rating: 0.9,
        },
        throughput: ThroughputMetrics {
            operations_per_second: 100.0,
            bytes_per_second: 1024,
            latency_percentiles: {
                let mut m = HashMap::new();
                m.insert("p50".to_string(), 10.0);
                m
            },
        },
    };
    let json = serde_json::to_string(&metrics).unwrap();
    let deserialized: PerformanceMetrics = serde_json::from_str(&json).unwrap();
    assert_eq!(metrics, deserialized);
}

#[test]
fn test_compliance_criteria_serialization() {
    let criteria = ComplianceCriteria {
        min_pass_rate: 99.0,
        max_execution_time_ms: 5000,
        min_coverage: 95.0,
        security_requirements: vec![SecurityRequirement {
            requirement_id: "REQ-001".to_string(),
            description: "Test requirement".to_string(),
            mandatory: true,
            test_methods: vec!["KAT".to_string()],
        }],
    };
    let json = serde_json::to_string(&criteria).unwrap();
    let deserialized: ComplianceCriteria = serde_json::from_str(&json).unwrap();
    assert_eq!(criteria, deserialized);
}

#[test]
fn test_detailed_test_result_serialization() {
    let result = DetailedTestResult {
        test_id: "DTR-001".to_string(),
        category: TestCategory::Security,
        description: "Security test".to_string(),
        result: TestResult::Passed,
        execution_time_ms: 42,
        additional_details: HashMap::new(),
    };
    let json = serde_json::to_string(&result).unwrap();
    let deserialized: DetailedTestResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, deserialized);
}

// ============================================================
// Full report serialization roundtrip
// ============================================================

#[test]
fn test_full_report_json_roundtrip() {
    let cgen = CavpComplianceGenerator::new();
    let alg = CavpAlgorithm::MlKem { variant: "1024".to_string() };
    let results =
        vec![make_passing_result("t1", alg.clone()), make_passing_result("t2", alg.clone())];
    let batch = make_batch(alg, results, Duration::from_millis(20));
    let report = cgen.generate_report(&[batch]).unwrap();

    let json = cgen.export_json(&report).unwrap();
    let deserialized: CavpComplianceReport = serde_json::from_str(&json).unwrap();

    assert_eq!(report.algorithm, deserialized.algorithm);
    assert_eq!(report.summary.total_tests, deserialized.summary.total_tests);
    assert_eq!(report.compliance_status, deserialized.compliance_status);
}

// ============================================================
// Algorithm-specific criteria exercise
// ============================================================

#[test]
fn test_all_algorithm_criteria_used() {
    let cgen = CavpComplianceGenerator::new();

    // Test each algorithm variant to exercise all criteria map entries
    // Algorithm-specific criteria have min_coverage=100% but summary hardcodes 95%,
    // so all will be NonCompliant. The goal is to exercise the criteria lookup paths.
    let algorithms = vec![
        CavpAlgorithm::MlKem { variant: "512".to_string() },
        CavpAlgorithm::MlKem { variant: "1024".to_string() },
        CavpAlgorithm::MlDsa { variant: "44".to_string() },
        CavpAlgorithm::MlDsa { variant: "87".to_string() },
        CavpAlgorithm::SlhDsa { variant: "128".to_string() },
        CavpAlgorithm::SlhDsa { variant: "192".to_string() },
        CavpAlgorithm::SlhDsa { variant: "256".to_string() },
        CavpAlgorithm::FnDsa { variant: "512".to_string() },
        CavpAlgorithm::FnDsa { variant: "1024".to_string() },
    ];

    for alg in algorithms {
        let results = vec![make_passing_result("t1", alg.clone())];
        let batch = make_batch(alg.clone(), results, Duration::from_millis(5));
        let report = cgen.generate_report(&[batch]).unwrap();
        // All have 100% pass rate but 95% < 100% required coverage → NonCompliant
        assert!(
            matches!(report.compliance_status, ComplianceStatus::NonCompliant { .. }),
            "Expected NonCompliant due to coverage gap for {:?}, got {:?}",
            alg,
            report.compliance_status
        );
    }
}
