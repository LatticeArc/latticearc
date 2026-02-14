#![deny(unsafe_code)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::panic)]
#![allow(clippy::indexing_slicing)]
#![allow(clippy::arithmetic_side_effects)]
#![allow(clippy::cast_precision_loss)]
#![allow(clippy::cast_possible_truncation)]
#![allow(missing_docs)]

//! Coverage tests for `Fips140_3Validator` methods that are not exercised by existing tests.
//!
//! Targets: `run_power_up_tests()`, `run_conditional_tests()`, `generate_compliance_certificate()`,
//! `is_power_up_completed()`, `should_run_conditional_tests()`, `test_vectors()`, and `Default`.

use arc_validation::fips_validation_impl::{
    Fips140_3ValidationResult, Fips140_3Validator, SelfTestResult, SelfTestType,
};
use chrono::Utc;

// ============================================================================
// Fips140_3Validator::run_power_up_tests
// ============================================================================

#[test]
fn test_run_power_up_tests_succeeds() {
    let mut validator = Fips140_3Validator::new("test-module".to_string(), 3);
    let result = validator.run_power_up_tests().expect("Power-up tests should succeed");
    assert!(result.validation_id.starts_with("FIPS140-3-"));
    assert_eq!(result.module_name, "test-module");
    assert_eq!(result.compliance_level, "FIPS 140-3 Level 3");
    assert!(!result.power_up_tests.is_empty());
    assert!(result.conditional_tests.is_empty());
}

#[test]
fn test_run_power_up_tests_has_seven_subtests() {
    let mut validator = Fips140_3Validator::new("module-seven".to_string(), 1);
    let result = validator.run_power_up_tests().unwrap();
    // Should have 7 subtests: AES key wrapping, hash functions, signature algorithms,
    // key encapsulation, RNG quality, pairwise consistency, zeroization
    assert_eq!(result.power_up_tests.len(), 7, "Expected 7 power-up subtests");
}

#[test]
fn test_run_power_up_tests_check_subtest_names() {
    let mut validator = Fips140_3Validator::new("test-names".to_string(), 1);
    let result = validator.run_power_up_tests().unwrap();

    let names: Vec<&str> = result.power_up_tests.iter().map(|t| t.test_name.as_str()).collect();
    assert!(names.contains(&"AES Key Wrapping Test"));
    assert!(names.contains(&"Hash Function Tests"));
    assert!(names.contains(&"Digital Signature Test"));
    assert!(names.contains(&"Key Encapsulation Randomness Test"));
    assert!(names.contains(&"Random Number Generator Quality Test"));
    assert!(names.contains(&"Pairwise Consistency Test"));
    assert!(names.contains(&"Memory Zeroization Test"));
}

#[test]
fn test_run_power_up_tests_algorithms() {
    let mut validator = Fips140_3Validator::new("algo-check".to_string(), 1);
    let result = validator.run_power_up_tests().unwrap();

    let algorithms: Vec<&str> =
        result.power_up_tests.iter().map(|t| t.algorithm.as_str()).collect();
    assert!(algorithms.contains(&"AES-256-GCM"));
    assert!(algorithms.contains(&"SHA-256, SHA3-256"));
    assert!(algorithms.contains(&"Ed25519"));
    assert!(algorithms.contains(&"HMAC-SHA256"));
    assert!(algorithms.contains(&"Zeroization"));
}

#[test]
fn test_run_power_up_tests_sets_power_up_completed() {
    let mut validator = Fips140_3Validator::new("complete-check".to_string(), 1);
    assert!(!validator.is_power_up_completed());

    let result = validator.run_power_up_tests().unwrap();
    // If all subtests passed, power_up_completed should be true
    if result.overall_passed {
        assert!(validator.is_power_up_completed());
    }
}

#[test]
fn test_run_power_up_tests_detailed_results() {
    let mut validator = Fips140_3Validator::new("detailed".to_string(), 2);
    let result = validator.run_power_up_tests().unwrap();

    // Verify detailed_results JSON has expected fields
    let details = &result.detailed_results;
    assert!(details.get("power_up_tests_count").is_some());
    assert!(details.get("passed_tests").is_some());
    assert!(details.get("test_coverage").is_some());
}

#[test]
fn test_run_power_up_tests_execution_time() {
    let mut validator = Fips140_3Validator::new("timing".to_string(), 1);
    let result = validator.run_power_up_tests().unwrap();

    // Execution time should be non-zero
    assert!(result.execution_time.as_nanos() > 0);

    // Each subtest should have its own execution time
    for subtest in &result.power_up_tests {
        // execution_time should be populated
        let _ = subtest.execution_time;
    }
}

// ============================================================================
// Fips140_3Validator::run_conditional_tests
// ============================================================================

#[test]
fn test_run_conditional_tests_succeeds() {
    let mut validator = Fips140_3Validator::new("cond-module".to_string(), 2);
    let result = validator.run_conditional_tests().expect("Conditional tests should succeed");
    assert!(result.validation_id.starts_with("FIPS140-3-COND-"));
    assert_eq!(result.module_name, "cond-module");
    assert!(result.power_up_tests.is_empty());
    assert!(!result.conditional_tests.is_empty());
}

#[test]
fn test_run_conditional_tests_has_four_subtests() {
    let mut validator = Fips140_3Validator::new("cond-count".to_string(), 1);
    let result = validator.run_conditional_tests().unwrap();
    // Should have 4 subtests: key integrity, operational environment, error detection, performance limits
    assert_eq!(result.conditional_tests.len(), 4, "Expected 4 conditional subtests");
}

#[test]
fn test_run_conditional_tests_check_subtest_names() {
    let mut validator = Fips140_3Validator::new("cond-names".to_string(), 1);
    let result = validator.run_conditional_tests().unwrap();

    let names: Vec<&str> = result.conditional_tests.iter().map(|t| t.test_name.as_str()).collect();
    assert!(names.contains(&"Key Integrity Test"));
    assert!(names.contains(&"Operational Environment Test"));
    assert!(names.contains(&"Error Detection Test"));
    assert!(names.contains(&"Performance Limits Test"));
}

#[test]
fn test_run_conditional_tests_all_pass() {
    let mut validator = Fips140_3Validator::new("all-pass".to_string(), 1);
    let result = validator.run_conditional_tests().unwrap();
    // All four conditional tests should pass
    assert!(result.overall_passed);
    for test in &result.conditional_tests {
        assert!(test.passed, "Test {} should pass", test.test_name);
    }
}

#[test]
fn test_run_conditional_tests_detailed_results() {
    let mut validator = Fips140_3Validator::new("cond-detail".to_string(), 1);
    let result = validator.run_conditional_tests().unwrap();
    let details = &result.detailed_results;
    assert!(details.get("conditional_tests_count").is_some());
    assert!(details.get("passed_tests").is_some());
    assert!(details.get("test_frequency").is_some());
}

// ============================================================================
// Fips140_3Validator::generate_compliance_certificate
// ============================================================================

#[test]
fn test_generate_compliance_certificate_power_up() {
    let mut validator = Fips140_3Validator::new("cert-module".to_string(), 3);
    let result = validator.run_power_up_tests().unwrap();
    let cert = validator.generate_compliance_certificate(&result);

    assert!(cert.contains("FIPS 140-3 COMPLIANCE CERTIFICATE"));
    assert!(cert.contains("Module: cert-module"));
    assert!(cert.contains("Compliance Level: FIPS 140-3 Level 3"));
    assert!(cert.contains("Power-Up Tests:"));
    assert!(cert.contains("[PASS]") || cert.contains("[FAIL]"));
    assert!(cert.contains("Total Execution Time:"));
    assert!(cert.contains("LatticeArc Validation Framework"));
}

#[test]
fn test_generate_compliance_certificate_conditional() {
    let mut validator = Fips140_3Validator::new("cert-cond".to_string(), 2);
    let result = validator.run_conditional_tests().unwrap();
    let cert = validator.generate_compliance_certificate(&result);

    assert!(cert.contains("Conditional Tests:"));
    assert!(cert.contains("cert-cond"));
}

#[test]
fn test_generate_compliance_certificate_empty_result() {
    let validator = Fips140_3Validator::new("cert-empty".to_string(), 1);
    let result = Fips140_3ValidationResult {
        validation_id: "VR-EMPTY".to_string(),
        timestamp: Utc::now(),
        power_up_tests: vec![],
        conditional_tests: vec![],
        overall_passed: true,
        compliance_level: "FIPS 140-3 Level 1".to_string(),
        module_name: "cert-empty".to_string(),
        execution_time: std::time::Duration::from_millis(1),
        detailed_results: serde_json::json!({}),
    };
    let cert = validator.generate_compliance_certificate(&result);

    assert!(cert.contains("PASSED"));
    // Should NOT contain "Power-Up Tests:" or "Conditional Tests:" sections
    assert!(!cert.contains("Power-Up Tests:"));
    assert!(!cert.contains("Conditional Tests:"));
}

#[test]
fn test_generate_compliance_certificate_failed_result() {
    let validator = Fips140_3Validator::new("cert-fail".to_string(), 1);
    let result = Fips140_3ValidationResult {
        validation_id: "VR-FAIL".to_string(),
        timestamp: Utc::now(),
        power_up_tests: vec![SelfTestResult {
            test_type: SelfTestType::PowerUp,
            test_name: "FailingTest".to_string(),
            algorithm: "TEST".to_string(),
            passed: false,
            execution_time: std::time::Duration::from_millis(1),
            timestamp: Utc::now(),
            details: serde_json::json!({}),
            error_message: Some("intentional failure".to_string()),
        }],
        conditional_tests: vec![],
        overall_passed: false,
        compliance_level: "FIPS 140-3 Level 1".to_string(),
        module_name: "cert-fail".to_string(),
        execution_time: std::time::Duration::from_millis(5),
        detailed_results: serde_json::json!({}),
    };
    let cert = validator.generate_compliance_certificate(&result);

    assert!(cert.contains("FAILED"));
    assert!(cert.contains("[FAIL] FailingTest"));
}

// ============================================================================
// Fips140_3Validator state methods
// ============================================================================

#[test]
fn test_is_power_up_completed_default_false() {
    let validator = Fips140_3Validator::new("state-check".to_string(), 1);
    assert!(!validator.is_power_up_completed());
}

#[test]
fn test_should_run_conditional_tests_after_creation() {
    let validator = Fips140_3Validator::new("cond-schedule".to_string(), 1);
    // Just created, last_conditional_test is now, so should NOT need to run yet
    assert!(!validator.should_run_conditional_tests());
}

#[test]
fn test_test_vectors_empty_initially() {
    let validator = Fips140_3Validator::new("vectors-check".to_string(), 1);
    assert!(validator.test_vectors().is_empty());
}

// ============================================================================
// Fips140_3Validator::default
// ============================================================================

#[test]
fn test_fips_validator_default() {
    let validator = Fips140_3Validator::default();
    assert!(!validator.is_power_up_completed());
    assert!(validator.test_vectors().is_empty());
    assert!(!validator.should_run_conditional_tests());
}

#[test]
fn test_fips_validator_default_run_power_up() {
    let mut validator = Fips140_3Validator::default();
    let result = validator.run_power_up_tests().unwrap();
    assert_eq!(result.module_name, "LatticeArc-Crypto");
    assert!(!result.power_up_tests.is_empty());
}

#[test]
fn test_fips_validator_default_run_conditional() {
    let mut validator = Fips140_3Validator::default();
    let result = validator.run_conditional_tests().unwrap();
    assert!(!result.conditional_tests.is_empty());
    assert!(result.overall_passed);
}

// ============================================================================
// Power-up then conditional in sequence
// ============================================================================

#[test]
fn test_full_validation_sequence() {
    let mut validator = Fips140_3Validator::new("full-seq".to_string(), 3);

    // Step 1: Power-up tests
    let power_result = validator.run_power_up_tests().unwrap();
    assert!(!power_result.power_up_tests.is_empty());

    // Step 2: Conditional tests
    let cond_result = validator.run_conditional_tests().unwrap();
    assert!(!cond_result.conditional_tests.is_empty());

    // Step 3: Certificate for each
    let power_cert = validator.generate_compliance_certificate(&power_result);
    let cond_cert = validator.generate_compliance_certificate(&cond_result);

    assert!(power_cert.contains("Power-Up Tests:"));
    assert!(cond_cert.contains("Conditional Tests:"));
}
