//! Simple CAVP tests
#![allow(clippy::unwrap_used)]
#![allow(clippy::redundant_clone)]
#![allow(clippy::float_cmp)]

use crate::cavp::pipeline::PipelineConfig;
use crate::cavp::storage::CavpStorage;
use crate::documentation::NistDocumentationGenerator;

/// Positive test: Verify CAVP framework basic functionality
#[test]
fn test_cavp_framework_basic_functionality() {
    let storage = crate::cavp::MemoryCavpStorage::new();

    let algorithm = crate::cavp::CavpAlgorithm::MlKem { variant: "768".to_string() };

    let test_result = crate::cavp::CavpTestResult::new(
        "test-001".to_string(),
        algorithm.clone(),
        "vector-001".to_string(),
        vec![1, 2, 3, 4],
        vec![1, 2, 3, 4],
        std::time::Duration::from_millis(100),
        crate::cavp::CavpTestMetadata::default(),
    );

    storage.store_result(&test_result).unwrap();

    let retrieved = storage.retrieve_result("test-001").unwrap();
    assert!(retrieved.is_some());
    let result = retrieved.unwrap();
    assert_eq!(result.test_id, "test-001");
    assert!(result.passed);
}

/// Positive test: Verify CAVP pipeline configuration
#[test]
fn test_cavp_pipeline_configuration() {
    let config = PipelineConfig {
        max_concurrent_tests: 4,
        test_timeout: std::time::Duration::from_secs(30),
        retry_count: 3,
        run_statistical_tests: true,
        generate_reports: true,
    };

    assert_eq!(config.max_concurrent_tests, 4);
    assert_eq!(config.test_timeout.as_secs(), 30);
    assert_eq!(config.retry_count, 3);
    assert!(config.run_statistical_tests);
    assert!(config.generate_reports);
}

/// Positive test: Verify CAVP compliance generator creation
#[test]
fn test_cavp_compliance_generator_creation() {
    let generator = crate::cavp::CavpComplianceGenerator::new();

    let algorithm = crate::cavp::CavpAlgorithm::MlKem { variant: "1024".to_string() };
    let test_result = crate::cavp::CavpTestResult::new(
        "test-002".to_string(),
        algorithm.clone(),
        "vector-002".to_string(),
        vec![5, 6, 7, 8],
        vec![5, 6, 7, 8],
        std::time::Duration::from_millis(200),
        crate::cavp::CavpTestMetadata::default(),
    );

    let mut batch = crate::cavp::CavpBatchResult::new("batch-002".to_string(), algorithm);
    batch.add_test_result(test_result);

    let report = generator.generate_report(&[batch]).unwrap();

    assert_eq!(report.algorithm.name(), "ML-KEM-1024");
    assert_eq!(report.summary.total_tests, 1);
    assert_eq!(report.summary.passed_tests, 1);
    assert_eq!(report.summary.pass_rate, 100.0);
}

/// Positive test: Verify NIST documentation generator creation
#[test]
fn test_nist_documentation_generator_creation() {
    let generator = NistDocumentationGenerator::new(
        "Test Organization".to_string(),
        "Test Module".to_string(),
        "1.0.0".to_string(),
    );

    let algorithm = crate::cavp::CavpAlgorithm::MlDsa { variant: "65".to_string() };

    let _test_metadata = crate::cavp::CavpTestMetadata {
        environment: crate::cavp::TestEnvironment::default(),
        security_level: 128,
        vector_version: "1.0".to_string(),
        implementation_version: "1.0.0".to_string(),
        configuration: crate::cavp::TestConfiguration::default(),
    };

    let test_result = crate::cavp::CavpTestResult::new(
        "test-003".to_string(),
        algorithm.clone(),
        "vector-003".to_string(),
        vec![9, 10, 11, 12],
        vec![9, 10, 11, 12],
        std::time::Duration::from_millis(300),
        crate::cavp::CavpTestMetadata::default(),
    );

    let mut batch = crate::cavp::CavpBatchResult::new("batch-003".to_string(), algorithm);
    batch.add_test_result(test_result);

    let compliance_generator = crate::cavp::CavpComplianceGenerator::new();
    let compliance_report = compliance_generator.generate_report(&[batch]).unwrap();
    let certificate = generator.generate_compliance_certificate(&compliance_report).unwrap();
    let technical_report = generator.generate_technical_report(&compliance_report).unwrap();
    let audit_trail = generator.generate_audit_trail(&[compliance_report]).unwrap();

    assert!(certificate.contains("NIST CAVP COMPLIANCE CERTIFICATE"));
    assert!(technical_report.contains("NIST CAVP TECHNICAL VALIDATION REPORT"));
    assert!(audit_trail.contains("NIST CAVP AUDIT TRAIL"));
}

/// Negative test: Verify CAVP framework handles errors correctly
#[test]
fn test_cavp_framework_error_handling() {
    let storage = crate::cavp::MemoryCavpStorage::new();

    let algorithm = crate::cavp::CavpAlgorithm::SlhDsa { variant: "128".to_string() };

    let failed_result = crate::cavp::CavpTestResult::failed(
        "test-fail".to_string(),
        algorithm.clone(),
        "vector-fail".to_string(),
        vec![1, 2, 3],
        vec![4, 5, 6],
        std::time::Duration::from_millis(50),
        "Expected mismatch".to_string(),
        crate::cavp::CavpTestMetadata::default(),
    );

    storage.store_result(&failed_result).unwrap();

    let retrieved = storage.retrieve_result("test-fail").unwrap();
    assert!(retrieved.is_some());

    let result = retrieved.unwrap();
    assert!(!result.passed);
    assert_eq!(result.error_message, Some("Expected mismatch".to_string()));
}

/// Positive test: Verify CAVP framework algorithm enumeration
#[test]
fn test_cavp_algorithm_enumeration() {
    let mlkem_768 = crate::cavp::CavpAlgorithm::MlKem { variant: "768".to_string() };
    let mldsa_65 = crate::cavp::CavpAlgorithm::MlDsa { variant: "65".to_string() };
    let slhdsa_128 = crate::cavp::CavpAlgorithm::SlhDsa { variant: "128".to_string() };
    let fndsa_512 = crate::cavp::CavpAlgorithm::FnDsa { variant: "512".to_string() };
    let hybrid_kem = crate::cavp::CavpAlgorithm::HybridKem;

    assert_eq!(mlkem_768.name(), "ML-KEM-768");
    assert_eq!(mldsa_65.name(), "ML-DSA-65");
    assert_eq!(slhdsa_128.name(), "SLH-DSA-128");
    assert_eq!(fndsa_512.name(), "FN-DSA-512");
    assert_eq!(hybrid_kem.name(), "Hybrid-KEM");

    assert_eq!(mlkem_768.fips_standard(), "FIPS 203");
    assert_eq!(mldsa_65.fips_standard(), "FIPS 204");
    assert_eq!(slhdsa_128.fips_standard(), "FIPS 205");
    assert_eq!(fndsa_512.fips_standard(), "FIPS 206");
    assert_eq!(hybrid_kem.fips_standard(), "FIPS 203 + FIPS 197");
}
