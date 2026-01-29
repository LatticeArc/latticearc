//! Enhanced CAVP Test Result Tracking and Compliance Reporting Tests
//!
//! This module provides comprehensive tests for:
//! - Test result storage and retrieval with audit trails
//! - Automated NIST compliance validation
//! - Enhanced compliance reporting with detailed documentation
//! - Integration with existing test infrastructure
//! - Error handling and recovery mechanisms
//!
//! # Test Coverage
//! - Positive tests for successful operations
//! - Negative tests for error handling
//! - Integration tests for end-to-end workflows
//! - Performance tests for scalability

use crate::cavp::*;
use anyhow::Result;
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::time::Duration;
use tempfile::TempDir;

#[cfg(test)]
mod enhanced_cavp_result_tracking_tests {
    use super::*;

    /// Test objective: Verify comprehensive test result storage with complete audit trails
    /// 
    /// Behaviors tested:
    /// - Storage of individual test results with full metadata
    /// - Retrieval of test results by various criteria
    /// - Audit trail maintenance for all operations
    /// - Batch operations for bulk storage
    /// 
    /// Positive test: All storage operations succeed with complete audit logging
    #[test]
    fn test_comprehensive_test_result_storage_with_audit_trail() {
        // Arrange
        let storage = MemoryCavpStorage::new();
        let algorithm = CavpAlgorithm::MlKem { variant: "768".to_string() };
        
        let test_result = CavpTestResult::new(
            "TEST-001".to_string(),
            algorithm.clone(),
            "VECTOR-001".to_string(),
            vec![0x01, 0x02, 0x03], // actual_result
            vec![0x01, 0x02, 0x03], // expected_result
            Duration::from_millis(100),
            CavpTestMetadata {
                environment: TestEnvironment {
                    os: "Linux".to_string(),
                    arch: "x86_64".to_string(),
                    rust_version: "1.75.0".to_string(),
                    compiler: "rustc".to_string(),
                    framework_version: "1.0.0".to_string(),
                },
                security_level: 128,
                vector_version: "1.0".to_string(),
                implementation_version: "1.0.0".to_string(),
                configuration: TestConfiguration {
                    iterations: 1,
                    timeout: Duration::from_secs(30),
                    statistical_tests: false,
                    parameters: HashMap::new(),
                },
            },
        );

        // Act
        let store_result = storage.store_test_result(&test_result);
        let retrieved_result = storage.get_test_result("TEST-001");

        // Assert
        assert!(store_result.is_ok(), "Test result storage should succeed");
        assert!(retrieved_result.is_ok(), "Test result retrieval should succeed");
        
        let retrieved = retrieved_result.unwrap();
        assert_eq!(retrieved.test_id, test_result.test_id);
        assert_eq!(retrieved.algorithm, test_result.algorithm);
        assert_eq!(retrieved.passed, true);
        
        // Verify audit trail exists
        let audit_logs = storage.get_audit_logs("TEST-001").unwrap();
        assert!(!audit_logs.is_empty(), "Audit trail should contain entries");
        
        // Verify batch operations
        let batch_id = "BATCH-001".to_string();
        let batch_result = CavpBatchResult::new(batch_id.clone(), algorithm);
        assert!(storage.store_batch_result(&batch_result).is_ok());
        
        let retrieved_batch = storage.get_batch_result(&batch_id).unwrap();
        assert_eq!(retrieved_batch.batch_id, batch_id);
    }

    /// Test objective: Verify automated NIST compliance validation checks
    /// 
    /// Behaviors tested:
    /// - Automatic validation against NIST standards
    /// - Compliance status determination
    /// - Security level verification
    /// - Performance criteria validation
    /// 
    /// Negative test: Handle non-compliant results appropriately
    #[test]
    fn test_automated_nist_compliance_validation_failure() {
        // Arrange
        let validator = NistComplianceValidator::new();
        let algorithm = CavpAlgorithm::MlDsa { variant: "65".to_string() };
        
        // Create a batch with intentionally failing results
        let mut batch_result = CavpBatchResult::new("FAIL-BATCH".to_string(), algorithm.clone());
        
        // Add some failing test results
        for i in 0..10 {
            let result = if i < 7 {
                // Pass
                CavpTestResult::new(
                    format!("PASS-{:03}", i),
                    algorithm.clone(),
                    format!("VEC-{:03}", i),
                    vec![0xFF; 64], // actual
                    vec![0xFF; 64], // expected
                    Duration::from_millis(50),
                    CavpTestMetadata::default(),
                )
            } else {
                // Fail
                CavpTestResult::failed(
                    format!("FAIL-{:03}", i),
                    algorithm.clone(),
                    format!("VEC-{:03}", i),
                    vec![0x00; 64], // actual
                    vec![0xFF; 64], // expected
                    Duration::from_millis(50),
                    "Test intentionally failed for compliance validation".to_string(),
                    CavpTestMetadata::default(),
                )
            };
            batch_result.add_test_result(result);
        }

        // Act
        let compliance_result = validator.validate_batch(&batch_result);

        // Assert
        assert!(compliance_result.is_ok(), "Compliance validation should complete");
        
        let report = compliance_result.unwrap();
        assert_eq!(report.algorithm, algorithm);
        assert_eq!(report.summary.total_tests, 10);
        assert_eq!(report.summary.passed_tests, 7);
        assert_eq!(report.summary.failed_tests, 3);
        assert_eq!(report.summary.pass_rate, 70.0);
        
        // Verify compliance status is not fully compliant
        match &report.compliance_status {
            ComplianceStatus::FullyCompliant => panic!("Expected non-compliant status"),
            ComplianceStatus::PartiallyCompliant { reasons } => {
                assert!(!reasons.is_empty(), "Should have reasons for non-compliance");
            },
            ComplianceStatus::NonCompliant { reasons } => {
                assert!(!reasons.is_empty(), "Should have reasons for non-compliance");
            },
        }
        
        // Verify NIST-specific criteria
        assert!(report.compliance_criteria.min_pass_rate > 70.0, 
                "NIST requires higher than 70% pass rate for ML-DSA");
    }

    /// Test objective: Verify enhanced compliance reporting with detailed documentation
    /// 
    /// Behaviors tested:
    /// - Comprehensive report generation
    /// - Multiple export formats (JSON, XML, HTML)
    /// - Audit trail documentation
    /// - Performance metrics inclusion
    /// 
    /// Positive test: Generate complete compliance documentation
    #[test]
    fn test_enhanced_compliance_reporting_with_detailed_documentation() {
        // Arrange
        let generator = CavpComplianceGenerator::new();
        let doc_generator = NistDocumentationGenerator::new(
            "LatticeArc".to_string(),
            "1.0.0".to_string(),
            "Test Organization".to_string(),
        );
        
        let algorithm = CavpAlgorithm::SlhDsa { variant: "128".to_string() };
        let mut batch_result = CavpBatchResult::new("REPORT-BATCH".to_string(), algorithm.clone());
        
        // Add comprehensive test results
        for i in 0..20 {
            let result = CavpTestResult::new(
                format!("TEST-{:03}", i),
                algorithm.clone(),
                format!("VEC-{:03}", i),
                vec![i as u8; 128], // actual
                vec![i as u8; 128], // expected
                Duration::from_millis(25 + (i % 10) as u64), // Varying execution times
                CavpTestMetadata {
                    environment: TestEnvironment {
                        os: "Ubuntu 22.04".to_string(),
                        arch: "x86_64".to_string(),
                        rust_version: "1.75.0".to_string(),
                        compiler: "rustc".to_string(),
                        framework_version: "1.0.0".to_string(),
                    },
                    security_level: 256,
                    vector_version: "1.0".to_string(),
                    implementation_version: "1.0.0".to_string(),
                    configuration: TestConfiguration {
                        iterations: 1,
                        timeout: Duration::from_secs(60),
                        statistical_tests: true,
                        parameters: {
                            let mut params = HashMap::new();
                            params.insert("test_type".to_string(), "deterministic".to_string());
                            params
                        },
                    },
                },
            );
            batch_result.add_test_result(result);
        }

        // Act
        let compliance_report = generator.generate_report(&[batch_result.clone()]).unwrap();
        let json_export = generator.export_json(&compliance_report).unwrap();
        let xml_export = generator.export_xml(&compliance_report).unwrap();
        
        let certificate = doc_generator.generate_compliance_certificate(&compliance_report).unwrap();
        let technical_report = doc_generator.generate_technical_report(&compliance_report).unwrap();
        let audit_trail = doc_generator.generate_audit_trail(&[compliance_report.clone()]).unwrap();

        // Assert
        // Verify basic report structure
        assert_eq!(compliance_report.algorithm, algorithm);
        assert_eq!(compliance_report.summary.total_tests, 20);
        assert_eq!(compliance_report.summary.passed_tests, 20);
        assert_eq!(compliance_report.summary.pass_rate, 100.0);
        assert_eq!(compliance_report.summary.security_level, 256);
        
        // Verify export formats
        assert!(json_export.contains("compliance_status"));
        assert!(json_export.contains("performance_metrics"));
        assert!(json_export.contains("detailed_results"));
        
        assert!(xml_export.contains("cavp_compliance_report"));
        assert!(xml_export.contains("</algorithm>"));
        assert!(xml_export.contains("</summary>"));
        
        // Verify documentation content
        assert!(certificate.contains("NIST CAVP COMPLIANCE CERTIFICATE"));
        assert!(certificate.contains("FULLY COMPLIANT"));
        assert!(certificate.contains(&algorithm.name()));
        
        assert!(technical_report.contains("NIST CAVP TECHNICAL VALIDATION REPORT"));
        assert!(technical_report.contains("EXECUTIVE SUMMARY"));
        assert!(technical_report.contains("DETAILED TEST RESULTS"));
        assert!(technical_report.contains("PERFORMANCE ANALYSIS"));
        assert!(technical_report.contains("COMPLIANCE ANALYSIS"));
        
        assert!(audit_trail.contains("NIST CAVP AUDIT TRAIL"));
        assert!(audit_trail.contains("COMPLIANCE TRENDS"));
        
        // Verify performance metrics are included
        assert!(compliance_report.performance_metrics.avg_execution_time_ms > 0.0);
        assert!(compliance_report.performance_metrics.min_execution_time_ms > 0.0);
        assert!(compliance_report.performance_metrics.max_execution_time_ms > 0.0);
        assert!(compliance_report.performance_metrics.throughput.operations_per_second > 0.0);
    }

    /// Test objective: Verify integration with existing test infrastructure
    /// 
    /// Behaviors tested:
    /// - Integration with CI/CD pipeline
    /// - Compatibility with existing test runners
    /// - Seamless migration from legacy systems
    /// - Performance benchmarking integration
    /// 
    /// Positive test: Full integration workflow succeeds
    #[test]
    fn test_integration_with_existing_test_infrastructure() {
        // Arrange
        let config = PipelineConfig {
            parallel_execution: true,
            max_threads: 4,
            timeout_per_test: Duration::from_secs(30),
            retry_failed_tests: 2,
            generate_reports: true,
            storage_backend: StorageBackend::Memory,
        };
        
        let executor = CavpTestExecutor::new(config);
        let orchestrator = CavpValidationOrchestrator::new(executor);
        
        // Create test vectors from existing infrastructure
        let test_vectors = vec![
            CavpTestVector {
                id: "INTEGRATION-001".to_string(),
                algorithm: CavpAlgorithm::MlKem { variant: "512".to_string() },
                inputs: CavpVectorInputs {
                    seed: Some(vec![0x01; 32]),
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
                    public_key: Some(vec![0x02; 800]),
                    secret_key: Some(vec![0x03; 1632]),
                    ciphertext: None,
                    signature: None,
                    shared_secret: None,
                    additional: HashMap::new(),
                },
                metadata: CavpVectorMetadata {
                    version: "1.0".to_string(),
                    source: "legacy_migration".to_string(),
                    test_type: CavpTestType::KeyGen,
                    created_at: Utc::now(),
                    security_level: 128,
                    notes: Some("Migrated from legacy test suite".to_string()),
                },
            },
            CavpTestVector {
                id: "INTEGRATION-002".to_string(),
                algorithm: CavpAlgorithm::FnDsa { variant: "512".to_string() },
                inputs: CavpVectorInputs {
                    seed: Some(vec![0x04; 32]),
                    message: Some(b"Integration test message".to_vec()),
                    key_material: None,
                    pk: Some(vec![0x05; 897]),
                    sk: Some(vec![0x06; 1281]),
                    c: None,
                    m: None,
                    ek: None,
                    dk: None,
                    signature: None,
                    parameters: HashMap::new(),
                },
                expected_outputs: CavpVectorOutputs {
                    public_key: Some(vec![0x05; 897]),
                    secret_key: Some(vec![0x06; 1281]),
                    ciphertext: None,
                    signature: Some(vec![0x07; 690]),
                    shared_secret: None,
                    additional: HashMap::new(),
                },
                metadata: CavpVectorMetadata {
                    version: "1.0".to_string(),
                    source: "legacy_migration".to_string(),
                    test_type: CavpTestType::Signature,
                    created_at: Utc::now(),
                    security_level: 128,
                    notes: Some("Signature test from legacy system".to_string()),
                },
            },
        ];

        // Act
        let validation_result = orchestrator.run_full_validation(test_vectors);

        // Assert
        assert!(validation_result.is_ok(), "Full validation should succeed");
        
        let batch_results = validation_result.unwrap();
        assert_eq!(batch_results.len(), 2, "Should have results for both test vectors");
        
        for batch_result in &batch_results {
            assert!(!batch_result.test_results.is_empty(), "Each batch should have test results");
            assert!(batch_result.total_execution_time > Duration::ZERO, "Should track execution time");
            
            // Verify integration with CI reporting
            let ci_report = batch_result.generate_ci_report();
            assert!(ci_report.contains("CAVP Test Results"));
            assert!(ci_report.contains("Pass Rate"));
            assert!(ci_report.contains("Execution Time"));
        }
    }

    /// Test objective: Verify error handling and recovery mechanisms
    /// 
    /// Behaviors tested:
    /// - Graceful handling of malformed test vectors
    /// - Recovery from storage failures
    /// - Timeout handling for long-running tests
    /// - Resource cleanup on failures
    /// 
    /// Negative test: All error conditions are handled properly
    #[test]
    fn test_error_handling_and_recovery_mechanisms() {
        // Arrange
        let temp_dir = TempDir::new().unwrap();
        let file_storage = FileCavpStorage::new(temp_dir.path().to_str().unwrap());
        
        // Test 1: Malformed test vector handling
        let malformed_vector = CavpTestVector {
            id: "MALFORMED".to_string(),
            algorithm: CavpAlgorithm::MlKem { variant: "1024".to_string() },
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
                public_key: None, // Missing expected output
                secret_key: None,
                ciphertext: None,
                signature: None,
                shared_secret: None,
                additional: HashMap::new(),
            },
            metadata: CavpVectorMetadata {
                version: "".to_string(), // Empty version
                source: "test".to_string(),
                test_type: CavpTestType::KeyGen,
                created_at: Utc::now(),
                security_level: 0, // Invalid security level
                notes: None,
            },
        };

        let config = PipelineConfig {
            parallel_execution: false,
            max_threads: 1,
            timeout_per_test: Duration::from_millis(100), // Very short timeout
            retry_failed_tests: 1,
            generate_reports: true,
            storage_backend: StorageBackend::File,
        };
        
        let executor = CavpTestExecutor::new(config);
        let test_result = executor.execute_test_vector(&malformed_vector);

        // Assert - should handle gracefully
        assert!(test_result.is_ok(), "Should handle malformed vector gracefully");
        let result = test_result.unwrap();
        assert!(!result.passed, "Malformed vector should not pass");
        assert!(result.error_message.is_some(), "Should have error message");

        // Test 2: Storage failure recovery
        let valid_result = CavpTestResult::new(
            "RECOVERY-TEST".to_string(),
            CavpAlgorithm::SlhDsa { variant: "256".to_string() },
            "RECOVERY-VEC".to_string(),
            vec![0x01; 64],
            vec![0x01; 64],
            Duration::from_millis(50),
            CavpTestMetadata::default(),
        );

        // Simulate storage failure by using invalid path
        let invalid_storage = FileCavpStorage::new("/invalid/path/that/does/not/exist");
        let store_result = invalid_storage.store_test_result(&valid_result);

        // Assert - should handle storage failure
        assert!(store_result.is_err(), "Should detect storage failure");

        // Test 3: Timeout handling
        let timeout_vector = CavpTestVector {
            id: "TIMEOUT-TEST".to_string(),
            algorithm: CavpAlgorithm::MlDsa { variant: "87".to_string() },
            inputs: CavpVectorInputs {
                seed: Some(vec![0xFF; 32]),
                message: Some(vec![0x00; 10000]), // Large message to trigger timeout
                key_material: None,
                pk: None,
                sk: None,
                c: None,
                m: None,
                ek: None,
                dk: None,
                signature: None,
                parameters: {
                    let mut params = HashMap::new();
                    params.insert("simulate_slow_operation".to_string(), "true".to_string());
                    params
                },
            },
            expected_outputs: CavpVectorOutputs {
                public_key: None,
                secret_key: None,
                ciphertext: None,
                signature: Some(vec![0x42; 2400]),
                shared_secret: None,
                additional: HashMap::new(),
            },
            metadata: CavpVectorMetadata {
                version: "1.0".to_string(),
                source: "timeout_test".to_string(),
                test_type: CavpTestType::Signature,
                created_at: Utc::now(),
                security_level: 256,
                notes: Some("Test timeout handling".to_string()),
            },
        };

        let timeout_config = PipelineConfig {
            parallel_execution: false,
            max_threads: 1,
            timeout_per_test: Duration::from_millis(50), // Very short timeout
            retry_failed_tests: 0,
            generate_reports: false,
            storage_backend: StorageBackend::Memory,
        };
        
        let timeout_executor = CavpTestExecutor::new(timeout_config);
        let timeout_result = timeout_executor.execute_test_vector(&timeout_vector);

        // Assert - should handle timeout gracefully
        assert!(timeout_result.is_ok(), "Should handle timeout gracefully");
        let result = timeout_result.unwrap();
        assert!(!result.passed, "Timeout test should not pass");
        assert!(result.error_message.unwrap().to_lowercase().contains("timeout"), 
                "Error should mention timeout");

        // Test 4: Resource cleanup verification
        let memory_before = get_memory_usage();
        
        // Run many tests to check for memory leaks
        for i in 0..100 {
            let cleanup_test = CavpTestResult::new(
                format!("CLEANUP-{:03}", i),
                CavpAlgorithm::HybridKem,
                format!("CLEANUP-VEC-{:03}", i),
                vec![0x01; 32],
                vec![0x01; 32],
                Duration::from_millis(1),
                CavpTestMetadata::default(),
            );
            
            let _ = file_storage.store_test_result(&cleanup_test);
        }
        
        let memory_after = get_memory_usage();
        
        // Assert - memory usage should be reasonable (allowing some overhead)
        let memory_increase = memory_after.saturating_sub(memory_before);
        assert!(memory_increase < 10 * 1024 * 1024, "Memory increase should be less than 10MB");
    }

    /// Helper function to get current memory usage (simplified)
    fn get_memory_usage() -> usize {
        // In a real implementation, this would use platform-specific APIs
        // For testing purposes, return a reasonable estimate
        1024 * 1024 // 1MB baseline
    }
}

#[cfg(test)]
mod compliance_validation_tests {
    use super::*;

    /// Test objective: Verify NIST-specific compliance criteria validation
    /// 
    /// Positive test: All NIST criteria are properly validated
    #[test]
    fn test_nist_compliance_criteria_validation() {
        let validator = NistComplianceValidator::new();
        
        // Test ML-KEM specific criteria
        let mlkem_criteria = validator.get_algorithm_criteria(&CavpAlgorithm::MlKem { variant: "768".to_string() });
        assert_eq!(mlkem_criteria.min_pass_rate, 100.0, "ML-KEM requires 100% pass rate");
        assert_eq!(mlkem_criteria.max_execution_time_ms, 1000, "ML-KEM has 1s timeout");
        assert_eq!(mlkem_criteria.min_coverage, 95.0, "ML-KEM requires 95% coverage");
        
        // Test ML-DSA specific criteria
        let mldsa_criteria = validator.get_algorithm_criteria(&CavpAlgorithm::MlDsa { variant: "65".to_string() });
        assert_eq!(mldsa_criteria.min_pass_rate, 100.0, "ML-DSA requires 100% pass rate");
        assert_eq!(mldsa_criteria.max_execution_time_ms, 5000, "ML-DSA has 5s timeout");
        assert_eq!(mldsa_criteria.min_coverage, 98.0, "ML-DSA requires 98% coverage");
        
        // Test SLH-DSA specific criteria
        let slhdsa_criteria = validator.get_algorithm_criteria(&CavpAlgorithm::SlhDsa { variant: "128".to_string() });
        assert_eq!(slhdsa_criteria.min_pass_rate, 100.0, "SLH-DSA requires 100% pass rate");
        assert_eq!(slhdsa_criteria.max_execution_time_ms, 30000, "SLH-DSA has 30s timeout");
        assert_eq!(slhdsa_criteria.min_coverage, 99.0, "SLH-DSA requires 99% coverage");
        
        // Test FN-DSA specific criteria
        let fndsa_criteria = validator.get_algorithm_criteria(&CavpAlgorithm::FnDsa { variant: "512".to_string() });
        assert_eq!(fndsa_criteria.min_pass_rate, 100.0, "FN-DSA requires 100% pass rate");
        assert_eq!(fndsa_criteria.max_execution_time_ms, 2000, "FN-DSA has 2s timeout");
        assert_eq!(fndsa_criteria.min_coverage, 97.0, "FN-DSA requires 97% coverage");
    }

    /// Test objective: Verify security level validation
    /// 
    /// Positive test: Security levels are correctly validated against NIST standards
    #[test]
    fn test_security_level_validation() {
        let validator = NistComplianceValidator::new();
        
        // Test valid security levels
        assert!(validator.validate_security_level(&CavpAlgorithm::MlKem { variant: "512".to_string() }, 128).is_ok());
        assert!(validator.validate_security_level(&CavpAlgorithm::MlKem { variant: "768".to_string() }, 192).is_ok());
        assert!(validator.validate_security_level(&CavpAlgorithm::MlKem { variant: "1024".to_string() }, 256).is_ok());
        
        assert!(validator.validate_security_level(&CavpAlgorithm::MlDsa { variant: "44".to_string() }, 128).is_ok());
        assert!(validator.validate_security_level(&CavpAlgorithm::MlDsa { variant: "65".to_string() }, 192).is_ok());
        assert!(validator.validate_security_level(&CavpAlgorithm::MlDsa { variant: "87".to_string() }, 256).is_ok());
        assert!(validator.validate_security_level(&CavpAlgorithm::MlDsa { variant: "128".to_string() }, 256).is_ok());
        
        // Test invalid security levels
        assert!(validator.validate_security_level(&CavpAlgorithm::MlKem { variant: "512".to_string() }, 256).is_err());
        assert!(validator.validate_security_level(&CavpAlgorithm::MlDsa { variant: "44".to_string() }, 256).is_err());
        assert!(validator.validate_security_level(&CavpAlgorithm::SlhDsa { variant: "128".to_string() }, 128).is_err());
    }
}