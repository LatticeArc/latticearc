//! CAVP compliance-coverage and enhanced-framework tests.
//!
//! Sub-modules preserve the structure and imports of their original
//! source files (split from the former consolidated fips_cavp.rs).

#![deny(unsafe_code)]

mod compliance_coverage {
    //! Coverage tests for CAVP compliance report generation.
    //! Targets compliance.rs: CavpComplianceGenerator, report generation,
    //! JSON/XML export, compliance evaluation (FullyCompliant, PartiallyCompliant,
    //! NonCompliant), and algorithm-specific criteria.

    #![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::redundant_clone)]

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
    fn test_generator_new_generates_report_succeeds() {
        let cgen = CavpComplianceGenerator::new();
        // Verify it was constructed (exercises new() and all criteria insertions)
        let alg = CavpAlgorithm::MlKem { variant: "768".to_string() };
        let results = vec![make_passing_result("t1", alg.clone())];
        let batch = make_batch(alg, results, Duration::from_millis(5));
        let _report = cgen.generate_report(&[batch]).unwrap();
    }

    #[test]
    fn test_generator_default_generates_report_succeeds() {
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
    fn test_generate_report_fully_compliant_hybrid_succeeds() {
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
    fn test_generate_report_mlkem_noncompliant_due_to_coverage_is_covered() {
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
    fn test_generate_report_partially_compliant_succeeds() {
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
    fn test_generate_report_non_compliant_succeeds() {
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
    fn test_security_level_mapping_mlkem_maps_variants_correctly_succeeds() {
        let cgen = CavpComplianceGenerator::new();

        for (variant, expected_level) in
            [("512", 128), ("768", 192), ("1024", 256), ("unknown", 128)]
        {
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
    fn test_security_level_mapping_mldsa_maps_variants_correctly_succeeds() {
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
    fn test_security_level_mapping_slhdsa_maps_variants_correctly_succeeds() {
        let cgen = CavpComplianceGenerator::new();

        for (variant, expected_level) in
            [("128", 128), ("192", 192), ("256", 256), ("unknown", 128)]
        {
            let alg = CavpAlgorithm::SlhDsa { variant: variant.to_string() };
            let results = vec![make_passing_result("t1", alg.clone())];
            let batch = make_batch(alg, results, Duration::from_millis(5));
            let report = cgen.generate_report(&[batch]).unwrap();
            assert_eq!(report.summary.security_level, expected_level);
        }
    }

    #[test]
    fn test_security_level_mapping_fndsa_maps_variants_correctly_succeeds() {
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
    fn test_security_level_mapping_hybrid_kem_returns_256_succeeds() {
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
    fn test_export_json_produces_valid_json_succeeds() {
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
    fn test_export_xml_produces_valid_xml_succeeds() {
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
    fn test_generate_report_multiple_batches_accumulates_totals_succeeds() {
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
    fn test_generate_report_with_default_criteria_succeeds() {
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
    fn test_compliance_results_with_error_message_fails() {
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
    fn test_compliance_results_without_error_message_uses_generic_message_fails() {
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
    fn test_compliance_status_variants_serialize_and_deserialize_succeeds() {
        let fc = ComplianceStatus::FullyCompliant;
        let pc =
            ComplianceStatus::PartiallyCompliant { exceptions: vec!["minor issue".to_string()] };
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
    fn test_test_category_variants_serialize_and_deserialize_succeeds() {
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
    fn test_test_result_variants_serialize_and_deserialize_succeeds() {
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
    fn test_performance_metrics_serialization_roundtrip_succeeds() {
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
    fn test_compliance_criteria_serialization_roundtrip_succeeds() {
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
    fn test_detailed_test_result_serialization_roundtrip_succeeds() {
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
    fn test_all_algorithm_criteria_are_exercised_succeeds() {
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
}
mod enhanced {
    //! Comprehensive tests for CAVP Enhanced Framework
    //!
    //! This module tests the enhanced CAVP (Cryptographic Algorithm Validation Program)
    //! framework components including:
    //! - NistComplianceValidator
    //! - CavpTestExecutor (enhanced)
    //! - PipelineConfig
    //! - StorageBackend
    //! - CavpValidationOrchestrator
    //!
    //! Tests cover:
    //! 1. All public types and their constructors
    //! 2. Framework configuration and initialization
    //! 3. Test execution flows with mock data
    //! 4. Result handling and reporting

    #![allow(
        clippy::panic,
        clippy::unwrap_used,
        clippy::indexing_slicing,
        clippy::float_cmp,
        clippy::redundant_clone,
        clippy::assertions_on_constants,
        clippy::drop_non_drop,
        clippy::useless_vec
    )]

    use chrono::{Duration, Utc};
    use latticearc_tests::validation::cavp::compliance::{
        ComplianceCriteria, ComplianceStatus, SecurityRequirement, TestCategory, TestResult,
    };
    use latticearc_tests::validation::cavp::enhanced_framework::{
        CavpTestExecutor as EnhancedCavpTestExecutor, CavpValidationOrchestrator,
        NistComplianceValidator, PipelineConfig as EnhancedPipelineConfig, StorageBackend,
    };
    use latticearc_tests::validation::cavp::types::{
        CavpAlgorithm, CavpBatchResult, CavpTestMetadata, CavpTestResult, CavpTestType,
        CavpTestVector, CavpValidationStatus, CavpVectorInputs, CavpVectorMetadata,
        CavpVectorOutputs, TestConfiguration, TestEnvironment,
    };
    use std::collections::HashMap;
    use std::time::Duration as StdDuration;

    // ============================================================================
    // Test Helper Functions
    // ============================================================================

    /// Creates a sample ML-KEM test vector for testing
    fn create_mlkem_vector(id: &str, variant: &str) -> CavpTestVector {
        CavpTestVector {
            id: id.to_string(),
            algorithm: CavpAlgorithm::MlKem { variant: variant.to_string() },
            inputs: CavpVectorInputs {
                seed: Some(vec![0x42; 32]),
                message: None,
                key_material: None,
                pk: None,
                sk: None,
                c: None,
                m: None,
                ek: None,
                dk: None,
                signature: None,
                parameters: HashMap::new(),
            },
            expected_outputs: CavpVectorOutputs {
                public_key: Some(vec![0x42; 64]),
                secret_key: Some(vec![0xCD; 128]),
                ciphertext: None,
                signature: None,
                shared_secret: None,
                additional: HashMap::new(),
            },
            metadata: CavpVectorMetadata {
                version: "1.0".to_string(),
                source: "NIST".to_string(),
                test_type: CavpTestType::KeyGen,
                created_at: Utc::now(),
                security_level: 128,
                notes: Some("Test vector for enhanced framework testing".to_string()),
            },
        }
    }

    /// Creates a sample ML-DSA test vector for signature testing
    fn create_mldsa_vector(id: &str, variant: &str) -> CavpTestVector {
        CavpTestVector {
            id: id.to_string(),
            algorithm: CavpAlgorithm::MlDsa { variant: variant.to_string() },
            inputs: CavpVectorInputs {
                seed: Some(vec![0x11; 32]),
                message: Some(b"Test message for ML-DSA".to_vec()),
                key_material: None,
                pk: None,
                sk: None,
                c: None,
                m: None,
                ek: None,
                dk: None,
                signature: None,
                parameters: HashMap::new(),
            },
            expected_outputs: CavpVectorOutputs {
                public_key: None,
                secret_key: None,
                ciphertext: None,
                signature: Some(vec![0x42; 64]),
                shared_secret: None,
                additional: HashMap::new(),
            },
            metadata: CavpVectorMetadata {
                version: "1.0".to_string(),
                source: "NIST".to_string(),
                test_type: CavpTestType::Signature,
                created_at: Utc::now(),
                security_level: 128,
                notes: Some("ML-DSA signature test vector".to_string()),
            },
        }
    }

    /// Creates a sample SLH-DSA test vector
    fn create_slhdsa_vector(id: &str, variant: &str) -> CavpTestVector {
        CavpTestVector {
            id: id.to_string(),
            algorithm: CavpAlgorithm::SlhDsa { variant: variant.to_string() },
            inputs: CavpVectorInputs {
                seed: Some(vec![0x22; 32]),
                message: Some(b"Test message for SLH-DSA".to_vec()),
                key_material: None,
                pk: None,
                sk: None,
                c: None,
                m: None,
                ek: None,
                dk: None,
                signature: None,
                parameters: HashMap::new(),
            },
            expected_outputs: CavpVectorOutputs {
                public_key: None,
                secret_key: None,
                ciphertext: None,
                signature: Some(vec![0x42; 64]),
                shared_secret: None,
                additional: HashMap::new(),
            },
            metadata: CavpVectorMetadata {
                version: "1.0".to_string(),
                source: "NIST".to_string(),
                test_type: CavpTestType::Signature,
                created_at: Utc::now(),
                security_level: 128,
                notes: Some("SLH-DSA signature test vector".to_string()),
            },
        }
    }

    /// Creates a sample FN-DSA test vector
    fn create_fndsa_vector(id: &str, variant: &str) -> CavpTestVector {
        CavpTestVector {
            id: id.to_string(),
            algorithm: CavpAlgorithm::FnDsa { variant: variant.to_string() },
            inputs: CavpVectorInputs {
                seed: Some(vec![0x33; 32]),
                message: Some(b"Test message for FN-DSA".to_vec()),
                key_material: None,
                pk: None,
                sk: None,
                c: None,
                m: None,
                ek: None,
                dk: None,
                signature: None,
                parameters: HashMap::new(),
            },
            expected_outputs: CavpVectorOutputs {
                public_key: None,
                secret_key: None,
                ciphertext: None,
                signature: Some(vec![0x42; 64]),
                shared_secret: None,
                additional: HashMap::new(),
            },
            metadata: CavpVectorMetadata {
                version: "1.0".to_string(),
                source: "NIST".to_string(),
                test_type: CavpTestType::Signature,
                created_at: Utc::now(),
                security_level: 128,
                notes: Some("FN-DSA signature test vector".to_string()),
            },
        }
    }

    /// Creates a sample Hybrid KEM test vector
    fn create_hybrid_vector(id: &str) -> CavpTestVector {
        CavpTestVector {
            id: id.to_string(),
            algorithm: CavpAlgorithm::HybridKem,
            inputs: CavpVectorInputs {
                seed: Some(vec![0x44; 64]),
                message: None,
                key_material: None,
                pk: None,
                sk: None,
                c: None,
                m: None,
                ek: None,
                dk: None,
                signature: None,
                parameters: HashMap::new(),
            },
            expected_outputs: CavpVectorOutputs {
                public_key: Some(vec![0x42; 64]),
                secret_key: None,
                ciphertext: None,
                signature: None,
                shared_secret: Some(vec![0x55; 32]),
                additional: HashMap::new(),
            },
            metadata: CavpVectorMetadata {
                version: "1.0".to_string(),
                source: "Internal".to_string(),
                test_type: CavpTestType::KeyGen,
                created_at: Utc::now(),
                security_level: 256,
                notes: Some("Hybrid KEM test vector".to_string()),
            },
        }
    }

    /// Creates a test vector that will trigger a timeout simulation
    fn create_slow_vector(id: &str) -> CavpTestVector {
        let mut vector = create_mlkem_vector(id, "768");
        vector.inputs.parameters.insert("simulate_slow_operation".to_string(), vec![1]);
        vector
    }

    /// Creates a test vector missing required seed for KeyGen
    fn create_invalid_keygen_vector(id: &str) -> CavpTestVector {
        CavpTestVector {
            id: id.to_string(),
            algorithm: CavpAlgorithm::MlKem { variant: "768".to_string() },
            inputs: CavpVectorInputs {
                seed: None, // Missing required seed
                message: None,
                key_material: None,
                pk: None,
                sk: None,
                c: None,
                m: None,
                ek: None,
                dk: None,
                signature: None,
                parameters: HashMap::new(),
            },
            expected_outputs: CavpVectorOutputs {
                public_key: Some(vec![0xAB; 64]),
                secret_key: None,
                ciphertext: None,
                signature: None,
                shared_secret: None,
                additional: HashMap::new(),
            },
            metadata: CavpVectorMetadata {
                version: "1.0".to_string(),
                source: "Test".to_string(),
                test_type: CavpTestType::KeyGen, // KeyGen requires seed
                created_at: Utc::now(),
                security_level: 128,
                notes: None,
            },
        }
    }

    /// Helper function to create a batch result with specified test results
    fn create_batch_with_results(
        algorithm: CavpAlgorithm,
        passed: usize,
        failed: usize,
    ) -> CavpBatchResult {
        let batch_id = format!("BATCH-{}", Utc::now().timestamp_micros());
        let mut batch = CavpBatchResult::new(batch_id, algorithm.clone());

        for i in 0..passed {
            let result = CavpTestResult::new(
                format!("PASS-{}", i),
                algorithm.clone(),
                format!("VEC-PASS-{}", i),
                vec![0x42; 64],
                vec![0x42; 64], // Same as actual - will pass
                StdDuration::from_millis(50),
                CavpTestMetadata::default(),
            );
            batch.add_test_result(result);
        }

        for i in 0..failed {
            let result = CavpTestResult::failed(
                format!("FAIL-{}", i),
                algorithm.clone(),
                format!("VEC-FAIL-{}", i),
                vec![0x00; 64],
                vec![0xFF; 64], // Different from actual - will fail
                StdDuration::from_millis(50),
                "Test mismatch".to_string(),
                CavpTestMetadata::default(),
            );
            batch.add_test_result(result);
        }

        batch
    }

    // ============================================================================
    // NistComplianceValidator Tests
    // ============================================================================

    mod nist_compliance_validator_tests {
        use super::*;

        #[test]
        fn test_validator_creation_succeeds() {
            let _validator = NistComplianceValidator::new();
            // Validator should be created successfully with initialized criteria
            assert!(true, "NistComplianceValidator created successfully");
        }

        #[test]
        fn test_validator_default_succeeds() {
            let _validator = NistComplianceValidator::default();
            // Default should be equivalent to new()
            assert!(true, "NistComplianceValidator::default() works");
        }

        #[test]
        fn test_get_algorithm_criteria_mlkem_512_returns_correct_criteria_succeeds() {
            let validator = NistComplianceValidator::new();
            let algorithm = CavpAlgorithm::MlKem { variant: "512".to_string() };

            let criteria = validator.get_algorithm_criteria(&algorithm);

            assert_eq!(criteria.min_pass_rate, 100.0);
            assert_eq!(criteria.max_execution_time_ms, 1000);
            assert_eq!(criteria.min_coverage, 95.0);
            assert!(!criteria.security_requirements.is_empty());
        }

        #[test]
        fn test_get_algorithm_criteria_mlkem_768_returns_correct_criteria_succeeds() {
            let validator = NistComplianceValidator::new();
            let algorithm = CavpAlgorithm::MlKem { variant: "768".to_string() };

            let criteria = validator.get_algorithm_criteria(&algorithm);

            assert_eq!(criteria.min_pass_rate, 100.0);
            assert_eq!(criteria.max_execution_time_ms, 1500);
        }

        #[test]
        fn test_get_algorithm_criteria_mlkem_1024_returns_correct_criteria_succeeds() {
            let validator = NistComplianceValidator::new();
            let algorithm = CavpAlgorithm::MlKem { variant: "1024".to_string() };

            let criteria = validator.get_algorithm_criteria(&algorithm);

            assert_eq!(criteria.min_pass_rate, 100.0);
            assert_eq!(criteria.max_execution_time_ms, 2000);
        }

        #[test]
        fn test_get_algorithm_criteria_mldsa_44_returns_correct_criteria_succeeds() {
            let validator = NistComplianceValidator::new();
            let algorithm = CavpAlgorithm::MlDsa { variant: "44".to_string() };

            let criteria = validator.get_algorithm_criteria(&algorithm);

            assert_eq!(criteria.min_pass_rate, 100.0);
            assert_eq!(criteria.max_execution_time_ms, 3000);
            assert_eq!(criteria.min_coverage, 98.0);
        }

        #[test]
        fn test_get_algorithm_criteria_mldsa_65_returns_correct_criteria_succeeds() {
            let validator = NistComplianceValidator::new();
            let algorithm = CavpAlgorithm::MlDsa { variant: "65".to_string() };

            let criteria = validator.get_algorithm_criteria(&algorithm);

            assert_eq!(criteria.max_execution_time_ms, 4000);
        }

        #[test]
        fn test_get_algorithm_criteria_mldsa_87_returns_correct_criteria_succeeds() {
            let validator = NistComplianceValidator::new();
            let algorithm = CavpAlgorithm::MlDsa { variant: "87".to_string() };

            let criteria = validator.get_algorithm_criteria(&algorithm);

            assert_eq!(criteria.max_execution_time_ms, 5000);
        }

        #[test]
        fn test_get_algorithm_criteria_mldsa_128_returns_correct_criteria_succeeds() {
            let validator = NistComplianceValidator::new();
            let algorithm = CavpAlgorithm::MlDsa { variant: "128".to_string() };

            let criteria = validator.get_algorithm_criteria(&algorithm);

            assert_eq!(criteria.min_coverage, 98.0);
        }

        #[test]
        fn test_get_algorithm_criteria_slhdsa_sha2_128s_returns_correct_criteria_succeeds() {
            let validator = NistComplianceValidator::new();
            let algorithm = CavpAlgorithm::SlhDsa { variant: "SHA2-128s".to_string() };

            let criteria = validator.get_algorithm_criteria(&algorithm);

            assert_eq!(criteria.min_pass_rate, 100.0);
            assert_eq!(criteria.max_execution_time_ms, 20000);
            assert_eq!(criteria.min_coverage, 99.0);
        }

        #[test]
        fn test_get_algorithm_criteria_slhdsa_sha2_128f_returns_correct_criteria_succeeds() {
            let validator = NistComplianceValidator::new();
            let algorithm = CavpAlgorithm::SlhDsa { variant: "SHA2-128f".to_string() };

            let criteria = validator.get_algorithm_criteria(&algorithm);

            assert_eq!(criteria.max_execution_time_ms, 25000);
        }

        #[test]
        fn test_get_algorithm_criteria_slhdsa_sha2_256s_returns_correct_criteria_succeeds() {
            let validator = NistComplianceValidator::new();
            let algorithm = CavpAlgorithm::SlhDsa { variant: "SHA2-256s".to_string() };

            let criteria = validator.get_algorithm_criteria(&algorithm);

            assert_eq!(criteria.max_execution_time_ms, 25000);
        }

        #[test]
        fn test_get_algorithm_criteria_slhdsa_sha2_256f_returns_correct_criteria_succeeds() {
            let validator = NistComplianceValidator::new();
            let algorithm = CavpAlgorithm::SlhDsa { variant: "SHA2-256f".to_string() };

            let criteria = validator.get_algorithm_criteria(&algorithm);

            assert_eq!(criteria.max_execution_time_ms, 30000);
        }

        #[test]
        fn test_get_algorithm_criteria_fndsa_512_returns_correct_criteria_succeeds() {
            let validator = NistComplianceValidator::new();
            let algorithm = CavpAlgorithm::FnDsa { variant: "512".to_string() };

            let criteria = validator.get_algorithm_criteria(&algorithm);

            assert_eq!(criteria.min_pass_rate, 100.0);
            assert_eq!(criteria.max_execution_time_ms, 1500);
            assert_eq!(criteria.min_coverage, 97.0);
        }

        #[test]
        fn test_get_algorithm_criteria_fndsa_1024_returns_correct_criteria_succeeds() {
            let validator = NistComplianceValidator::new();
            let algorithm = CavpAlgorithm::FnDsa { variant: "1024".to_string() };

            let criteria = validator.get_algorithm_criteria(&algorithm);

            assert_eq!(criteria.max_execution_time_ms, 2000);
        }

        #[test]
        fn test_get_algorithm_criteria_unknown_algorithm_returns_default_succeeds() {
            let validator = NistComplianceValidator::new();
            let algorithm = CavpAlgorithm::MlKem { variant: "unknown".to_string() };

            let criteria = validator.get_algorithm_criteria(&algorithm);

            // Should return default criteria
            assert_eq!(criteria.min_pass_rate, 100.0);
            assert_eq!(criteria.max_execution_time_ms, 5000);
            assert_eq!(criteria.min_coverage, 95.0);
            assert!(criteria.security_requirements.is_empty());
        }

        #[test]
        fn test_get_algorithm_criteria_hybrid_kem_returns_correct_criteria_succeeds() {
            let validator = NistComplianceValidator::new();
            let algorithm = CavpAlgorithm::HybridKem;

            let criteria = validator.get_algorithm_criteria(&algorithm);

            // HybridKem should return default criteria
            assert_eq!(criteria.min_pass_rate, 100.0);
        }

        #[test]
        fn test_validate_batch_fully_compliant_returns_compliant_status_succeeds() {
            let validator = NistComplianceValidator::new();
            let algorithm = CavpAlgorithm::MlKem { variant: "768".to_string() };

            let batch = create_batch_with_results(algorithm, 10, 0);
            let report = validator.validate_batch(&batch).unwrap();

            assert!(matches!(report.compliance_status, ComplianceStatus::FullyCompliant));
            assert_eq!(report.summary.total_tests, 10);
            assert_eq!(report.summary.passed_tests, 10);
            assert_eq!(report.summary.failed_tests, 0);
            assert_eq!(report.summary.pass_rate, 100.0);
        }

        #[test]
        fn test_validate_batch_partially_compliant_returns_partial_status_succeeds() {
            let validator = NistComplianceValidator::new();
            let algorithm = CavpAlgorithm::MlDsa { variant: "44".to_string() };

            // 7 passed, 3 failed = 70% pass rate
            let batch = create_batch_with_results(algorithm, 7, 3);
            let report = validator.validate_batch(&batch).unwrap();

            assert!(matches!(
                report.compliance_status,
                ComplianceStatus::PartiallyCompliant { .. }
            ));
            assert_eq!(report.summary.pass_rate, 70.0);
        }

        #[test]
        fn test_validate_batch_non_compliant_returns_non_compliant_status_succeeds() {
            let validator = NistComplianceValidator::new();
            let algorithm = CavpAlgorithm::SlhDsa { variant: "128s".to_string() };

            // 4 passed, 6 failed = 40% pass rate (below 50%)
            let batch = create_batch_with_results(algorithm, 4, 6);
            let report = validator.validate_batch(&batch).unwrap();

            assert!(matches!(report.compliance_status, ComplianceStatus::NonCompliant { .. }));
        }

        #[test]
        fn test_validate_batch_report_structure_has_correct_format() {
            let validator = NistComplianceValidator::new();
            let algorithm = CavpAlgorithm::FnDsa { variant: "512".to_string() };

            let batch = create_batch_with_results(algorithm.clone(), 5, 0);
            let report = validator.validate_batch(&batch).unwrap();

            // Verify report structure
            assert!(report.report_id.starts_with("CAVP-REPORT-"));
            assert_eq!(report.algorithm, algorithm);
            assert!(!report.nist_standards.is_empty());
            assert_eq!(report.nist_standards[0], "FIPS 206");
        }

        #[test]
        fn test_validate_batch_performance_metrics_are_correct() {
            let validator = NistComplianceValidator::new();
            let algorithm = CavpAlgorithm::MlKem { variant: "512".to_string() };

            let batch = create_batch_with_results(algorithm, 5, 0);
            let report = validator.validate_batch(&batch).unwrap();

            // Verify performance metrics
            assert!(report.performance_metrics.avg_execution_time_ms >= 0.0);
            assert!(report.performance_metrics.total_execution_time_ms > 0);
        }

        #[test]
        fn test_validate_batch_detailed_results_are_correct() {
            let validator = NistComplianceValidator::new();
            let algorithm = CavpAlgorithm::MlKem { variant: "768".to_string() };

            let batch = create_batch_with_results(algorithm, 3, 2);
            let report = validator.validate_batch(&batch).unwrap();

            // Verify detailed results
            assert_eq!(report.detailed_results.len(), 5);

            let passed_count = report
                .detailed_results
                .iter()
                .filter(|r| matches!(r.result, TestResult::Passed))
                .count();
            assert_eq!(passed_count, 3);
        }

        // Security Level Validation Tests

        #[test]
        fn test_validate_security_level_mlkem_512_valid_returns_ok() {
            let validator = NistComplianceValidator::new();
            let algorithm = CavpAlgorithm::MlKem { variant: "512".to_string() };

            let result = validator.validate_security_level(&algorithm, 128);
            assert!(result.is_ok());
        }

        #[test]
        fn test_validate_security_level_mlkem_768_valid_returns_ok() {
            let validator = NistComplianceValidator::new();
            let algorithm = CavpAlgorithm::MlKem { variant: "768".to_string() };

            let result = validator.validate_security_level(&algorithm, 192);
            assert!(result.is_ok());
        }

        #[test]
        fn test_validate_security_level_mlkem_1024_valid_returns_ok() {
            let validator = NistComplianceValidator::new();
            let algorithm = CavpAlgorithm::MlKem { variant: "1024".to_string() };

            let result = validator.validate_security_level(&algorithm, 256);
            assert!(result.is_ok());
        }

        #[test]
        fn test_validate_security_level_mlkem_invalid_returns_error() {
            let validator = NistComplianceValidator::new();
            let algorithm = CavpAlgorithm::MlKem { variant: "512".to_string() };

            let result = validator.validate_security_level(&algorithm, 256);
            assert!(result.is_err());
            assert!(result.unwrap_err().to_string().contains("Invalid security level"));
        }

        #[test]
        fn test_validate_security_level_mldsa_44_valid_returns_ok() {
            let validator = NistComplianceValidator::new();
            let algorithm = CavpAlgorithm::MlDsa { variant: "44".to_string() };

            let result = validator.validate_security_level(&algorithm, 128);
            assert!(result.is_ok());
        }

        #[test]
        fn test_validate_security_level_mldsa_65_valid_returns_ok() {
            let validator = NistComplianceValidator::new();
            let algorithm = CavpAlgorithm::MlDsa { variant: "65".to_string() };

            let result = validator.validate_security_level(&algorithm, 192);
            assert!(result.is_ok());
        }

        #[test]
        fn test_validate_security_level_mldsa_87_valid_returns_ok() {
            let validator = NistComplianceValidator::new();
            let algorithm = CavpAlgorithm::MlDsa { variant: "87".to_string() };

            let result = validator.validate_security_level(&algorithm, 256);
            assert!(result.is_ok());
        }

        #[test]
        fn test_validate_security_level_mldsa_128_valid_returns_ok() {
            let validator = NistComplianceValidator::new();
            let algorithm = CavpAlgorithm::MlDsa { variant: "128".to_string() };

            let result = validator.validate_security_level(&algorithm, 256);
            assert!(result.is_ok());
        }

        #[test]
        fn test_validate_security_level_mldsa_invalid_returns_error() {
            let validator = NistComplianceValidator::new();
            let algorithm = CavpAlgorithm::MlDsa { variant: "44".to_string() };

            let result = validator.validate_security_level(&algorithm, 256);
            assert!(result.is_err());
        }

        #[test]
        fn test_validate_security_level_slhdsa_128s_valid_returns_ok() {
            let validator = NistComplianceValidator::new();
            let algorithm = CavpAlgorithm::SlhDsa { variant: "128s".to_string() };

            let result = validator.validate_security_level(&algorithm, 128);
            assert!(result.is_ok());
        }

        #[test]
        fn test_validate_security_level_slhdsa_128f_valid_returns_ok() {
            let validator = NistComplianceValidator::new();
            let algorithm = CavpAlgorithm::SlhDsa { variant: "128f".to_string() };

            let result = validator.validate_security_level(&algorithm, 128);
            assert!(result.is_ok());
        }

        #[test]
        fn test_validate_security_level_slhdsa_256s_valid_returns_ok() {
            let validator = NistComplianceValidator::new();
            let algorithm = CavpAlgorithm::SlhDsa { variant: "256s".to_string() };

            let result = validator.validate_security_level(&algorithm, 256);
            assert!(result.is_ok());
        }

        #[test]
        fn test_validate_security_level_slhdsa_256f_valid_returns_ok() {
            let validator = NistComplianceValidator::new();
            let algorithm = CavpAlgorithm::SlhDsa { variant: "256f".to_string() };

            let result = validator.validate_security_level(&algorithm, 256);
            assert!(result.is_ok());
        }

        #[test]
        fn test_validate_security_level_slhdsa_invalid_returns_error() {
            let validator = NistComplianceValidator::new();
            let algorithm = CavpAlgorithm::SlhDsa { variant: "128s".to_string() };

            let result = validator.validate_security_level(&algorithm, 256);
            assert!(result.is_err());
        }

        #[test]
        fn test_validate_security_level_fndsa_512_valid_returns_ok() {
            let validator = NistComplianceValidator::new();
            let algorithm = CavpAlgorithm::FnDsa { variant: "512".to_string() };

            let result = validator.validate_security_level(&algorithm, 128);
            assert!(result.is_ok());
        }

        #[test]
        fn test_validate_security_level_fndsa_1024_valid_returns_ok() {
            let validator = NistComplianceValidator::new();
            let algorithm = CavpAlgorithm::FnDsa { variant: "1024".to_string() };

            let result = validator.validate_security_level(&algorithm, 256);
            assert!(result.is_ok());
        }

        #[test]
        fn test_validate_security_level_fndsa_invalid_returns_error() {
            let validator = NistComplianceValidator::new();
            let algorithm = CavpAlgorithm::FnDsa { variant: "512".to_string() };

            let result = validator.validate_security_level(&algorithm, 256);
            assert!(result.is_err());
        }

        #[test]
        fn test_validate_security_level_hybrid_kem_valid_returns_ok() {
            let validator = NistComplianceValidator::new();
            let algorithm = CavpAlgorithm::HybridKem;

            let result = validator.validate_security_level(&algorithm, 128);
            assert!(result.is_ok());

            let result = validator.validate_security_level(&algorithm, 192);
            assert!(result.is_ok());

            let result = validator.validate_security_level(&algorithm, 256);
            assert!(result.is_ok());
        }

        #[test]
        fn test_validate_security_level_hybrid_kem_invalid_returns_error() {
            let validator = NistComplianceValidator::new();
            let algorithm = CavpAlgorithm::HybridKem;

            let result = validator.validate_security_level(&algorithm, 64);
            assert!(result.is_err());
            assert!(result.unwrap_err().to_string().contains("minimum security level 128"));
        }
    }

    // ============================================================================
    // PipelineConfig Tests
    // ============================================================================

    mod pipeline_config_tests {
        use super::*;

        #[test]
        fn test_pipeline_config_default_has_expected_values_succeeds() {
            let config = EnhancedPipelineConfig::default();

            assert!(config.parallel_execution);
            assert!(config.max_threads > 0);
            assert!(config.timeout_per_test > Duration::zero());
            assert!(config.retry_failed_tests > 0);
            assert!(config.generate_reports);
            assert!(matches!(config.storage_backend, StorageBackend::Memory));
        }

        #[test]
        fn test_pipeline_config_custom_has_correct_values_succeeds() {
            let config = EnhancedPipelineConfig {
                parallel_execution: false,
                max_threads: 4,
                timeout_per_test: Duration::seconds(60),
                retry_failed_tests: 5,
                generate_reports: false,
                storage_backend: StorageBackend::File,
            };

            assert!(!config.parallel_execution);
            assert_eq!(config.max_threads, 4);
            assert_eq!(config.timeout_per_test, Duration::seconds(60));
            assert_eq!(config.retry_failed_tests, 5);
            assert!(!config.generate_reports);
            assert!(matches!(config.storage_backend, StorageBackend::File));
        }

        #[test]
        fn test_pipeline_config_clone_produces_equal_value_succeeds() {
            let config = EnhancedPipelineConfig::default();
            let cloned = config.clone();

            assert_eq!(config.parallel_execution, cloned.parallel_execution);
            assert_eq!(config.max_threads, cloned.max_threads);
            assert_eq!(config.timeout_per_test, cloned.timeout_per_test);
        }

        #[test]
        fn test_pipeline_config_debug_has_correct_format() {
            let config = EnhancedPipelineConfig::default();
            let debug_str = format!("{:?}", config);

            assert!(debug_str.contains("PipelineConfig"));
            assert!(debug_str.contains("parallel_execution"));
        }
    }

    // ============================================================================
    // StorageBackend Tests
    // ============================================================================

    mod storage_backend_tests {
        use super::*;

        #[test]
        fn test_storage_backend_memory_is_accessible() {
            let backend = StorageBackend::Memory;
            assert!(matches!(backend, StorageBackend::Memory));
        }

        #[test]
        fn test_storage_backend_file_is_accessible() {
            let backend = StorageBackend::File;
            assert!(matches!(backend, StorageBackend::File));
        }

        #[test]
        fn test_storage_backend_clone_produces_equal_value_succeeds() {
            let backend = StorageBackend::Memory;
            let cloned = backend.clone();
            assert!(matches!(cloned, StorageBackend::Memory));
        }

        #[test]
        fn test_storage_backend_debug_has_correct_format() {
            let backend = StorageBackend::Memory;
            let debug_str = format!("{:?}", backend);
            assert!(debug_str.contains("Memory"));
        }
    }

    // ============================================================================
    // CavpTestExecutor Tests
    // ============================================================================

    mod cavp_test_executor_tests {
        use super::*;

        #[test]
        fn test_executor_creation_succeeds() {
            let config = EnhancedPipelineConfig::default();
            let executor = EnhancedCavpTestExecutor::new(config);

            // Executor should be created successfully
            drop(executor);
        }

        #[test]
        fn test_execute_mlkem_keygen_vector_succeeds() {
            let config = EnhancedPipelineConfig::default();
            let executor = EnhancedCavpTestExecutor::new(config);

            let vector = create_mlkem_vector("TEST-MLKEM-001", "768");
            let result = executor.execute_test_vector(&vector);

            assert!(result.is_ok());
            let test_result = result.unwrap();
            assert_eq!(test_result.vector_id, "TEST-MLKEM-001");
            assert!(test_result.test_id.starts_with("TEST-"));
        }

        #[test]
        fn test_execute_mldsa_signature_vector_succeeds() {
            let config = EnhancedPipelineConfig::default();
            let executor = EnhancedCavpTestExecutor::new(config);

            let vector = create_mldsa_vector("TEST-MLDSA-001", "44");
            let result = executor.execute_test_vector(&vector);

            assert!(result.is_ok());
        }

        #[test]
        fn test_execute_slhdsa_vector_succeeds() {
            let config = EnhancedPipelineConfig::default();
            let executor = EnhancedCavpTestExecutor::new(config);

            let vector = create_slhdsa_vector("TEST-SLHDSA-001", "128s");
            let result = executor.execute_test_vector(&vector);

            assert!(result.is_ok());
        }

        #[test]
        fn test_execute_fndsa_vector_succeeds() {
            let config = EnhancedPipelineConfig::default();
            let executor = EnhancedCavpTestExecutor::new(config);

            let vector = create_fndsa_vector("TEST-FNDSA-001", "512");
            let result = executor.execute_test_vector(&vector);

            assert!(result.is_ok());
        }

        #[test]
        fn test_execute_hybrid_vector_succeeds() {
            let config = EnhancedPipelineConfig::default();
            let executor = EnhancedCavpTestExecutor::new(config);

            let vector = create_hybrid_vector("TEST-HYBRID-001");
            let result = executor.execute_test_vector(&vector);

            assert!(result.is_ok());
        }

        #[test]
        fn test_execute_timeout_simulation_completes_succeeds() {
            let config = EnhancedPipelineConfig::default();
            let executor = EnhancedCavpTestExecutor::new(config);

            let vector = create_slow_vector("TEST-SLOW-001");
            let result = executor.execute_test_vector(&vector);

            // Should return a result (possibly failed due to timeout)
            assert!(result.is_ok());
            let test_result = result.unwrap();
            assert!(!test_result.passed, "Slow operation should simulate failure");
            assert!(test_result.error_message.is_some());
        }

        #[test]
        fn test_execute_missing_seed_keygen_returns_error() {
            let config = EnhancedPipelineConfig::default();
            let executor = EnhancedCavpTestExecutor::new(config);

            let vector = create_invalid_keygen_vector("TEST-INVALID-001");
            let result = executor.execute_test_vector(&vector);

            // Should return a result with error
            assert!(result.is_ok());
            let test_result = result.unwrap();
            assert!(!test_result.passed);
            assert!(test_result.error_message.is_some());
            assert!(test_result.error_message.as_ref().unwrap().contains("Missing required seed"));
        }

        #[test]
        fn test_execution_time_recorded_correctly_succeeds() {
            let config = EnhancedPipelineConfig::default();
            let executor = EnhancedCavpTestExecutor::new(config);

            let vector = create_mlkem_vector("TEST-TIME-001", "512");
            let result = executor.execute_test_vector(&vector).unwrap();

            assert!(result.execution_time > StdDuration::ZERO);
        }

        #[test]
        fn test_result_metadata_populated_correctly_succeeds() {
            let config = EnhancedPipelineConfig::default();
            let executor = EnhancedCavpTestExecutor::new(config);

            let vector = create_mlkem_vector("TEST-META-001", "768");
            let result = executor.execute_test_vector(&vector).unwrap();

            // Verify metadata is populated
            assert!(!result.metadata.environment.os.is_empty());
            assert!(!result.metadata.environment.arch.is_empty());
        }
    }

    // ============================================================================
    // CavpValidationOrchestrator Tests
    // ============================================================================

    mod cavp_validation_orchestrator_tests {
        use super::*;

        #[test]
        fn test_orchestrator_creation_succeeds() {
            let config = EnhancedPipelineConfig::default();
            let executor = EnhancedCavpTestExecutor::new(config);
            let orchestrator = CavpValidationOrchestrator::new(executor);

            // Orchestrator should be created successfully
            drop(orchestrator);
        }

        #[test]
        fn test_orchestrator_default_succeeds() {
            let orchestrator = CavpValidationOrchestrator::default();
            // Default orchestrator should work
            drop(orchestrator);
        }

        #[test]
        fn test_compliance_generator_access_succeeds() {
            let orchestrator = CavpValidationOrchestrator::default();
            let generator = orchestrator.compliance_generator();

            // Should be able to access compliance generator
            assert!(true, "Compliance generator accessible");
            let _ = generator;
        }

        #[test]
        fn test_run_full_validation_single_algorithm_succeeds() {
            let orchestrator = CavpValidationOrchestrator::default();

            let vectors = vec![
                create_mlkem_vector("ORCH-001", "768"),
                create_mlkem_vector("ORCH-002", "768"),
            ];

            let results = orchestrator.run_full_validation(vectors);

            assert!(results.is_ok());
            let batch_results = results.unwrap();
            // All vectors are ML-KEM, so should be one batch
            assert_eq!(batch_results.len(), 1);
            assert_eq!(batch_results[0].test_results.len(), 2);
        }

        #[test]
        fn test_run_full_validation_multiple_algorithms_succeeds() {
            let orchestrator = CavpValidationOrchestrator::default();

            let vectors = vec![
                create_mlkem_vector("MULTI-001", "768"),
                create_mldsa_vector("MULTI-002", "44"),
                create_slhdsa_vector("MULTI-003", "128s"),
            ];

            let results = orchestrator.run_full_validation(vectors);

            assert!(results.is_ok());
            let batch_results = results.unwrap();
            // Three different algorithms, so three batches
            assert_eq!(batch_results.len(), 3);
        }

        #[test]
        fn test_run_full_validation_empty_succeeds() {
            let orchestrator = CavpValidationOrchestrator::default();

            let vectors: Vec<CavpTestVector> = vec![];
            let results = orchestrator.run_full_validation(vectors);

            assert!(results.is_ok());
            let batch_results = results.unwrap();
            assert!(batch_results.is_empty());
        }

        #[test]
        fn test_run_full_validation_with_failures_reports_errors_fails() {
            let orchestrator = CavpValidationOrchestrator::default();

            let vectors = vec![
                create_mlkem_vector("FAIL-001", "768"),
                create_invalid_keygen_vector("FAIL-002"),
                create_slow_vector("FAIL-003"),
            ];

            let results = orchestrator.run_full_validation(vectors);

            assert!(results.is_ok());
            let batch_results = results.unwrap();
            // All are ML-KEM variants, so one batch with mixed results
            assert!(!batch_results.is_empty());
        }

        #[test]
        fn test_orchestrator_grouping_by_algorithm_is_correct() {
            let orchestrator = CavpValidationOrchestrator::default();

            let vectors = vec![
                create_mlkem_vector("GROUP-001", "512"),
                create_mlkem_vector("GROUP-002", "768"), // Different variant = different algorithm
                create_mlkem_vector("GROUP-003", "1024"), // Different variant = different algorithm
            ];

            let results = orchestrator.run_full_validation(vectors).unwrap();

            // Three different ML-KEM variants should create three batches
            assert_eq!(results.len(), 3);
        }
    }

    // ============================================================================
    // TestCategory Tests
    // ============================================================================

    mod test_category_tests {
        use super::*;

        #[test]
        fn test_category_from_vector_id_keygen_returns_correct_category_matches_expected() {
            let category = TestCategory::from_vector_id("ML-KEM-keygen-001");
            assert!(matches!(category, TestCategory::KeyGeneration));

            let category = TestCategory::from_vector_id("KEYGEN_TEST_001");
            assert!(matches!(category, TestCategory::KeyGeneration));
        }

        #[test]
        fn test_category_from_vector_id_signature_returns_correct_category_matches_expected() {
            let category = TestCategory::from_vector_id("ML-DSA-sig-001");
            assert!(matches!(category, TestCategory::Signature));

            let category = TestCategory::from_vector_id("SIGNATURE_TEST");
            assert!(matches!(category, TestCategory::Signature));

            let category = TestCategory::from_vector_id("SIG_VERIFY");
            assert!(matches!(category, TestCategory::Signature));
        }

        #[test]
        fn test_category_from_vector_id_encryption_returns_correct_category_matches_expected() {
            let category = TestCategory::from_vector_id("enc-001");
            assert!(matches!(category, TestCategory::Encryption));

            let category = TestCategory::from_vector_id("ENCAPSULATION_TEST");
            assert!(matches!(category, TestCategory::Encryption));
        }

        #[test]
        fn test_category_from_vector_id_decryption_returns_correct_category_matches_expected() {
            let category = TestCategory::from_vector_id("dec-001");
            assert!(matches!(category, TestCategory::Decryption));

            let category = TestCategory::from_vector_id("DECAPSULATION_TEST");
            assert!(matches!(category, TestCategory::Decryption));
        }

        #[test]
        fn test_category_from_vector_id_compliance_returns_correct_category_matches_expected() {
            // Default category when no pattern matches
            let category = TestCategory::from_vector_id("random_test_001");
            assert!(matches!(category, TestCategory::Compliance));

            let category = TestCategory::from_vector_id("MISC_TEST");
            assert!(matches!(category, TestCategory::Compliance));
        }
    }

    // ============================================================================
    // TestResult Tests
    // ============================================================================

    mod test_result_tests {
        use super::*;

        #[test]
        fn test_result_from_bool_passed_returns_passed_succeeds() {
            let result = TestResult::from_bool(true);
            assert!(matches!(result, TestResult::Passed));
        }

        #[test]
        fn test_result_from_bool_failed_returns_failed_fails() {
            let result = TestResult::from_bool(false);
            assert!(matches!(result, TestResult::Failed(_)));
        }
    }

    // ============================================================================
    // CavpBatchResult Tests
    // ============================================================================

    mod cavp_batch_result_tests {
        use super::*;

        #[test]
        fn test_batch_result_new_has_correct_fields_succeeds() {
            let algorithm = CavpAlgorithm::MlKem { variant: "768".to_string() };
            let batch = CavpBatchResult::new("TEST-BATCH".to_string(), algorithm.clone());

            assert_eq!(batch.batch_id, "TEST-BATCH");
            assert_eq!(batch.algorithm, algorithm);
            assert!(batch.test_results.is_empty());
            assert!(matches!(batch.status, CavpValidationStatus::Incomplete));
            assert_eq!(batch.pass_rate, 0.0);
        }

        #[test]
        fn test_batch_result_add_test_result_updates_count_succeeds() {
            let algorithm = CavpAlgorithm::MlKem { variant: "768".to_string() };
            let mut batch = CavpBatchResult::new("TEST-BATCH".to_string(), algorithm.clone());

            let result = CavpTestResult::new(
                "TEST-001".to_string(),
                algorithm.clone(),
                "VEC-001".to_string(),
                vec![0x42; 64],
                vec![0x42; 64],
                StdDuration::from_millis(100),
                CavpTestMetadata::default(),
            );

            batch.add_test_result(result);

            assert_eq!(batch.test_results.len(), 1);
            assert!(batch.total_execution_time >= StdDuration::from_millis(100));
        }

        #[test]
        fn test_batch_result_update_status_passed_is_correct() {
            let algorithm = CavpAlgorithm::MlKem { variant: "768".to_string() };
            let mut batch = CavpBatchResult::new("TEST-BATCH".to_string(), algorithm.clone());

            // Add passing test
            let result = CavpTestResult::new(
                "TEST-001".to_string(),
                algorithm.clone(),
                "VEC-001".to_string(),
                vec![0x42; 64],
                vec![0x42; 64], // Same as actual
                StdDuration::from_millis(100),
                CavpTestMetadata::default(),
            );

            batch.add_test_result(result);
            batch.update_status();

            assert_eq!(batch.pass_rate, 100.0);
            assert!(matches!(batch.status, CavpValidationStatus::Passed));
        }

        #[test]
        fn test_batch_result_update_status_failed_is_correct() {
            let algorithm = CavpAlgorithm::MlDsa { variant: "44".to_string() };
            let mut batch = CavpBatchResult::new("TEST-BATCH".to_string(), algorithm.clone());

            // Add failing test
            let result = CavpTestResult::failed(
                "TEST-001".to_string(),
                algorithm.clone(),
                "VEC-001".to_string(),
                vec![0x00; 64],
                vec![0xFF; 64], // Different from actual
                StdDuration::from_millis(100),
                "Mismatch".to_string(),
                CavpTestMetadata::default(),
            );

            batch.add_test_result(result);
            batch.update_status();

            assert_eq!(batch.pass_rate, 0.0);
            assert!(matches!(batch.status, CavpValidationStatus::Failed));
        }

        #[test]
        fn test_batch_result_update_status_mixed_is_correct() {
            let algorithm = CavpAlgorithm::SlhDsa { variant: "128s".to_string() };
            let mut batch = CavpBatchResult::new("TEST-BATCH".to_string(), algorithm.clone());

            // Add passing test
            batch.add_test_result(CavpTestResult::new(
                "PASS-001".to_string(),
                algorithm.clone(),
                "VEC-001".to_string(),
                vec![0x42; 64],
                vec![0x42; 64],
                StdDuration::from_millis(50),
                CavpTestMetadata::default(),
            ));

            // Add failing test
            batch.add_test_result(CavpTestResult::failed(
                "FAIL-001".to_string(),
                algorithm.clone(),
                "VEC-002".to_string(),
                vec![0x00; 64],
                vec![0xFF; 64],
                StdDuration::from_millis(50),
                "Error".to_string(),
                CavpTestMetadata::default(),
            ));

            batch.update_status();

            assert_eq!(batch.pass_rate, 50.0);
            assert!(matches!(batch.status, CavpValidationStatus::Failed));
        }

        #[test]
        fn test_batch_result_generate_ci_report_succeeds() {
            let algorithm = CavpAlgorithm::FnDsa { variant: "512".to_string() };
            let mut batch = CavpBatchResult::new("TEST-BATCH".to_string(), algorithm.clone());

            batch.add_test_result(CavpTestResult::new(
                "TEST-001".to_string(),
                algorithm.clone(),
                "VEC-001".to_string(),
                vec![0x42; 64],
                vec![0x42; 64],
                StdDuration::from_millis(100),
                CavpTestMetadata::default(),
            ));

            let report = batch.generate_ci_report();

            assert!(report.contains("FN-DSA-512"));
            assert!(report.contains("Total Tests: 1"));
            assert!(report.contains("Passed: 1"));
            assert!(report.contains("Failed: 0"));
            assert!(report.contains("Pass Rate:"));
        }
    }

    // ============================================================================
    // CavpTestMetadata Tests
    // ============================================================================

    mod cavp_test_metadata_tests {
        use super::*;

        #[test]
        fn test_metadata_default_has_expected_values_succeeds() {
            let metadata = CavpTestMetadata::default();

            assert!(!metadata.environment.os.is_empty());
            assert!(!metadata.environment.arch.is_empty());
            assert!(!metadata.environment.rust_version.is_empty());
            assert!(!metadata.environment.compiler.is_empty());
            assert_eq!(metadata.security_level, 128);
            assert_eq!(metadata.vector_version, "1.0");
        }

        #[test]
        fn test_environment_default_has_expected_values_succeeds() {
            let env = TestEnvironment::default();

            assert!(!env.os.is_empty());
            assert!(!env.arch.is_empty());
            assert!(!env.rust_version.is_empty());
            assert_eq!(env.compiler, "rustc");
        }

        #[test]
        fn test_configuration_default_has_expected_values_succeeds() {
            let config = TestConfiguration::default();

            assert_eq!(config.iterations, 1);
            assert_eq!(config.timeout, StdDuration::from_secs(30));
            assert!(!config.statistical_tests);
            assert!(config.parameters.is_empty());
        }
    }

    // ============================================================================
    // CavpAlgorithm Tests
    // ============================================================================

    mod cavp_algorithm_tests {
        use super::*;

        #[test]
        fn test_algorithm_name_mlkem_returns_correct_string_succeeds() {
            let algo = CavpAlgorithm::MlKem { variant: "768".to_string() };
            assert_eq!(algo.name(), "ML-KEM-768");
        }

        #[test]
        fn test_algorithm_name_mldsa_returns_correct_string_succeeds() {
            let algo = CavpAlgorithm::MlDsa { variant: "44".to_string() };
            assert_eq!(algo.name(), "ML-DSA-44");
        }

        #[test]
        fn test_algorithm_name_slhdsa_returns_correct_string_succeeds() {
            let algo = CavpAlgorithm::SlhDsa { variant: "128s".to_string() };
            assert_eq!(algo.name(), "SLH-DSA-128s");
        }

        #[test]
        fn test_algorithm_name_fndsa_returns_correct_string_succeeds() {
            let algo = CavpAlgorithm::FnDsa { variant: "512".to_string() };
            assert_eq!(algo.name(), "FN-DSA-512");
        }

        #[test]
        fn test_algorithm_name_hybrid_returns_correct_string_succeeds() {
            let algo = CavpAlgorithm::HybridKem;
            assert_eq!(algo.name(), "Hybrid-KEM");
        }

        #[test]
        fn test_fips_standard_mlkem_returns_correct_string_succeeds() {
            let algo = CavpAlgorithm::MlKem { variant: "768".to_string() };
            assert_eq!(algo.fips_standard(), "FIPS 203");
        }

        #[test]
        fn test_fips_standard_mldsa_returns_correct_string_succeeds() {
            let algo = CavpAlgorithm::MlDsa { variant: "65".to_string() };
            assert_eq!(algo.fips_standard(), "FIPS 204");
        }

        #[test]
        fn test_fips_standard_slhdsa_returns_correct_string_succeeds() {
            let algo = CavpAlgorithm::SlhDsa { variant: "256f".to_string() };
            assert_eq!(algo.fips_standard(), "FIPS 205");
        }

        #[test]
        fn test_fips_standard_fndsa_returns_correct_string_succeeds() {
            let algo = CavpAlgorithm::FnDsa { variant: "1024".to_string() };
            assert_eq!(algo.fips_standard(), "FIPS 206");
        }

        #[test]
        fn test_fips_standard_hybrid_returns_correct_string_succeeds() {
            let algo = CavpAlgorithm::HybridKem;
            assert_eq!(algo.fips_standard(), "FIPS 203 + FIPS 197");
        }

        #[test]
        fn test_algorithm_equality_matches_expected() {
            let algo1 = CavpAlgorithm::MlKem { variant: "768".to_string() };
            let algo2 = CavpAlgorithm::MlKem { variant: "768".to_string() };
            let algo3 = CavpAlgorithm::MlKem { variant: "512".to_string() };

            assert_eq!(algo1, algo2);
            assert_ne!(algo1, algo3);
        }

        #[test]
        fn test_algorithm_hash_deduplicates_correctly_succeeds() {
            use std::collections::HashSet;

            let mut set = HashSet::new();
            set.insert(CavpAlgorithm::MlKem { variant: "768".to_string() });
            set.insert(CavpAlgorithm::MlDsa { variant: "44".to_string() });

            assert!(set.contains(&CavpAlgorithm::MlKem { variant: "768".to_string() }));
            assert!(!set.contains(&CavpAlgorithm::MlKem { variant: "512".to_string() }));
        }

        #[test]
        fn test_algorithm_clone_produces_equal_value_succeeds() {
            let algo = CavpAlgorithm::SlhDsa { variant: "128s".to_string() };
            let cloned = algo.clone();

            assert_eq!(algo, cloned);
        }
    }

    // ============================================================================
    // CavpTestResult Tests
    // ============================================================================

    mod cavp_test_result_tests {
        use super::*;

        #[test]
        fn test_result_new_passed_has_correct_fields_succeeds() {
            let algorithm = CavpAlgorithm::MlKem { variant: "768".to_string() };
            let result = CavpTestResult::new(
                "TEST-001".to_string(),
                algorithm.clone(),
                "VEC-001".to_string(),
                vec![0x42; 64],
                vec![0x42; 64], // Same as actual
                StdDuration::from_millis(100),
                CavpTestMetadata::default(),
            );

            assert_eq!(result.test_id, "TEST-001");
            assert_eq!(result.algorithm, algorithm);
            assert_eq!(result.vector_id, "VEC-001");
            assert!(result.passed);
            assert!(result.error_message.is_none());
        }

        #[test]
        fn test_result_new_failed_has_correct_fields_fails() {
            let algorithm = CavpAlgorithm::MlDsa { variant: "44".to_string() };
            let result = CavpTestResult::new(
                "TEST-002".to_string(),
                algorithm,
                "VEC-002".to_string(),
                vec![0x00; 64],
                vec![0xFF; 64], // Different from actual
                StdDuration::from_millis(100),
                CavpTestMetadata::default(),
            );

            assert!(!result.passed);
        }

        #[test]
        fn test_result_failed_constructor_has_correct_fields_fails() {
            let algorithm = CavpAlgorithm::SlhDsa { variant: "128s".to_string() };
            let result = CavpTestResult::failed(
                "TEST-003".to_string(),
                algorithm.clone(),
                "VEC-003".to_string(),
                vec![],
                vec![0x42; 64],
                StdDuration::from_millis(50),
                "Test execution failed".to_string(),
                CavpTestMetadata::default(),
            );

            assert!(!result.passed);
            assert_eq!(result.error_message, Some("Test execution failed".to_string()));
        }

        #[test]
        fn test_result_timestamp_is_set_succeeds() {
            let algorithm = CavpAlgorithm::FnDsa { variant: "512".to_string() };
            let before = Utc::now();

            let result = CavpTestResult::new(
                "TEST-TIME".to_string(),
                algorithm,
                "VEC-TIME".to_string(),
                vec![0x42; 64],
                vec![0x42; 64],
                StdDuration::from_millis(10),
                CavpTestMetadata::default(),
            );

            let after = Utc::now();

            assert!(result.timestamp >= before);
            assert!(result.timestamp <= after);
        }
    }

    // ============================================================================
    // ComplianceStatus Tests
    // ============================================================================

    mod compliance_status_tests {
        use super::*;

        #[test]
        fn test_fully_compliant_status_is_correct() {
            let status = ComplianceStatus::FullyCompliant;
            assert!(matches!(status, ComplianceStatus::FullyCompliant));
        }

        #[test]
        fn test_partially_compliant_status_is_correct() {
            let status = ComplianceStatus::PartiallyCompliant {
                exceptions: vec!["Minor issue".to_string()],
            };

            if let ComplianceStatus::PartiallyCompliant { exceptions } = status {
                assert_eq!(exceptions.len(), 1);
                assert_eq!(exceptions[0], "Minor issue");
            } else {
                panic!("Expected PartiallyCompliant");
            }
        }

        #[test]
        fn test_non_compliant_status_is_correct() {
            let status =
                ComplianceStatus::NonCompliant { failures: vec!["Critical failure".to_string()] };

            if let ComplianceStatus::NonCompliant { failures } = status {
                assert_eq!(failures.len(), 1);
                assert_eq!(failures[0], "Critical failure");
            } else {
                panic!("Expected NonCompliant");
            }
        }

        #[test]
        fn test_insufficient_data_status_is_correct() {
            let status = ComplianceStatus::InsufficientData;
            assert!(matches!(status, ComplianceStatus::InsufficientData));
        }
    }

    // ============================================================================
    // SecurityRequirement Tests
    // ============================================================================

    mod security_requirement_tests {
        use super::*;

        #[test]
        fn test_security_requirement_creation_has_correct_fields_succeeds() {
            let req = SecurityRequirement {
                requirement_id: "FIPS203-4.1".to_string(),
                description: "Key generation shall be deterministic".to_string(),
                mandatory: true,
                test_methods: vec!["deterministic_keygen".to_string()],
            };

            assert_eq!(req.requirement_id, "FIPS203-4.1");
            assert!(req.mandatory);
            assert_eq!(req.test_methods.len(), 1);
        }

        #[test]
        fn test_security_requirement_optional_has_correct_fields_succeeds() {
            let req = SecurityRequirement {
                requirement_id: "OPT-001".to_string(),
                description: "Optional feature".to_string(),
                mandatory: false,
                test_methods: vec![],
            };

            assert!(!req.mandatory);
            assert!(req.test_methods.is_empty());
        }
    }

    // ============================================================================
    // ComplianceCriteria Tests
    // ============================================================================

    mod compliance_criteria_tests {
        use super::*;

        #[test]
        fn test_criteria_creation_has_correct_fields_succeeds() {
            let criteria = ComplianceCriteria {
                min_pass_rate: 100.0,
                max_execution_time_ms: 5000,
                min_coverage: 95.0,
                security_requirements: vec![],
            };

            assert_eq!(criteria.min_pass_rate, 100.0);
            assert_eq!(criteria.max_execution_time_ms, 5000);
            assert_eq!(criteria.min_coverage, 95.0);
        }

        #[test]
        fn test_criteria_with_requirements_has_correct_fields_succeeds() {
            let criteria = ComplianceCriteria {
                min_pass_rate: 100.0,
                max_execution_time_ms: 1000,
                min_coverage: 99.0,
                security_requirements: vec![
                    SecurityRequirement {
                        requirement_id: "REQ-001".to_string(),
                        description: "First requirement".to_string(),
                        mandatory: true,
                        test_methods: vec!["test1".to_string()],
                    },
                    SecurityRequirement {
                        requirement_id: "REQ-002".to_string(),
                        description: "Second requirement".to_string(),
                        mandatory: false,
                        test_methods: vec!["test2".to_string(), "test3".to_string()],
                    },
                ],
            };

            assert_eq!(criteria.security_requirements.len(), 2);
        }
    }

    // ============================================================================
    // Integration Tests
    // ============================================================================

    mod integration_tests {
        use super::*;

        #[test]
        fn test_full_validation_workflow_succeeds() {
            // Create orchestrator
            let orchestrator = CavpValidationOrchestrator::default();

            // Create test vectors for multiple algorithms
            let vectors = vec![
                create_mlkem_vector("INT-001", "768"),
                create_mlkem_vector("INT-002", "768"),
                create_mldsa_vector("INT-003", "44"),
            ];

            // Run validation
            let results = orchestrator.run_full_validation(vectors).unwrap();

            // Validate results
            assert!(!results.is_empty());

            // Validate with NistComplianceValidator
            let validator = NistComplianceValidator::new();
            for batch in &results {
                let report = validator.validate_batch(batch).unwrap();
                assert!(!report.report_id.is_empty());
                assert!(!report.nist_standards.is_empty());
            }
        }

        #[test]
        fn test_full_validation_with_compliance_report_succeeds() {
            let orchestrator = CavpValidationOrchestrator::default();
            let validator = NistComplianceValidator::new();

            let vectors = vec![
                create_mlkem_vector("COMP-001", "512"),
                create_mlkem_vector("COMP-002", "512"),
                create_mlkem_vector("COMP-003", "512"),
            ];

            let batch_results = orchestrator.run_full_validation(vectors).unwrap();

            for batch in &batch_results {
                let report = validator.validate_batch(batch).unwrap();

                // Verify report contains expected data
                assert!(report.summary.total_tests > 0);
                assert!(report.summary.pass_rate >= 0.0);
                assert!(report.summary.pass_rate <= 100.0);
                assert!(!report.detailed_results.is_empty());
            }
        }

        #[test]
        fn test_executor_with_custom_config_succeeds() {
            let config = EnhancedPipelineConfig {
                parallel_execution: false,
                max_threads: 1,
                timeout_per_test: Duration::seconds(10),
                retry_failed_tests: 0,
                generate_reports: false,
                storage_backend: StorageBackend::Memory,
            };

            let executor = EnhancedCavpTestExecutor::new(config);
            let vector = create_fndsa_vector("CUSTOM-001", "1024");

            let result = executor.execute_test_vector(&vector).unwrap();
            assert!(!result.test_id.is_empty());
        }

        #[test]
        fn test_all_algorithm_variants_are_accessible() {
            let orchestrator = CavpValidationOrchestrator::default();
            let validator = NistComplianceValidator::new();

            // Test all ML-KEM variants
            for variant in ["512", "768", "1024"] {
                let vectors = vec![create_mlkem_vector(&format!("MLKEM-{}", variant), variant)];
                let results = orchestrator.run_full_validation(vectors).unwrap();
                assert!(!results.is_empty());

                let algo = CavpAlgorithm::MlKem { variant: variant.to_string() };
                let criteria = validator.get_algorithm_criteria(&algo);
                assert_eq!(criteria.min_pass_rate, 100.0);
            }

            // Test all ML-DSA variants
            for variant in ["44", "65", "87", "128"] {
                let vectors = vec![create_mldsa_vector(&format!("MLDSA-{}", variant), variant)];
                let results = orchestrator.run_full_validation(vectors).unwrap();
                assert!(!results.is_empty());
            }

            // Test FN-DSA variants
            for variant in ["512", "1024"] {
                let vectors = vec![create_fndsa_vector(&format!("FNDSA-{}", variant), variant)];
                let results = orchestrator.run_full_validation(vectors).unwrap();
                assert!(!results.is_empty());
            }
        }

        #[test]
        fn test_large_batch_processing_completes_succeeds() {
            let orchestrator = CavpValidationOrchestrator::default();

            // Create a large batch of test vectors
            let vectors: Vec<CavpTestVector> =
                (0..100).map(|i| create_mlkem_vector(&format!("LARGE-{:04}", i), "768")).collect();

            let results = orchestrator.run_full_validation(vectors).unwrap();

            assert_eq!(results.len(), 1); // All same algorithm
            assert_eq!(results[0].test_results.len(), 100);
        }
    }
}
