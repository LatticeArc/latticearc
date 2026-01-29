#![deny(unsafe_code)]
#![allow(missing_docs)]
#![warn(clippy::unwrap_used)]
#![deny(clippy::panic)]
// JUSTIFICATION: FIPS validation orchestrator for 140-3 compliance.
// - Executes algorithm and policy tests against NIST standards
// - Statistical aggregation for compliance scoring
// - Test infrastructure prioritizes correctness verification
#![allow(clippy::arithmetic_side_effects)]
#![allow(clippy::cast_precision_loss)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::indexing_slicing)]

//! FIPSValidator - Main FIPS validation orchestrator

use arc_prelude::error::LatticeArcError;
use chrono::Utc;
use std::collections::HashMap;

use super::algorithm_tests::{test_aes_algorithm, test_mlkem_algorithm, test_sha3_algorithm};
use super::interface_tests::{test_api_interfaces, test_key_management};
use super::policy_tests::{test_error_handling, test_self_tests};
use super::types::{
    FIPSLevel, IssueSeverity, TestResult, ValidationCertificate, ValidationIssue, ValidationResult,
    ValidationScope,
};

/// Main FIPS validator
pub struct FIPSValidator {
    pub(crate) scope: ValidationScope,
}

impl FIPSValidator {
    /// Create a new FIPS validator
    #[must_use]
    pub fn new(scope: ValidationScope) -> Self {
        Self { scope }
    }

    /// Validate cryptographic module against FIPS requirements.
    ///
    /// # Errors
    /// Returns an error if algorithm, interface, or security policy validation fails.
    pub fn validate_module(&self) -> Result<ValidationResult, LatticeArcError> {
        let validation_id = format!("fips-val-{}", uuid::Uuid::new_v4());
        let start_time = std::time::Instant::now();

        tracing::info!("Starting FIPS validation: {}", validation_id);

        let mut issues = Vec::new();
        let mut test_results = HashMap::new();

        // Run validation tests based on scope
        match self.scope {
            ValidationScope::AlgorithmsOnly => {
                Self::validate_algorithms(&mut issues, &mut test_results)?;
            }
            ValidationScope::ModuleInterfaces => {
                Self::validate_algorithms(&mut issues, &mut test_results)?;
                Self::validate_interfaces(&mut issues, &mut test_results)?;
            }
            ValidationScope::FullModule => {
                Self::validate_algorithms(&mut issues, &mut test_results)?;
                Self::validate_interfaces(&mut issues, &mut test_results)?;
                Self::validate_security_policy(&mut issues, &mut test_results)?;
            }
        }

        let duration = start_time.elapsed().as_millis() as u64;

        // Determine overall validation status
        let is_valid = issues.iter().all(|i| i.severity != IssueSeverity::Critical);
        let level = Self::determine_security_level(&issues, &test_results);

        let result = ValidationResult {
            validation_id,
            timestamp: Utc::now(),
            scope: self.scope,
            is_valid,
            level,
            issues,
            test_results: test_results.clone(),
            metadata: HashMap::from([
                ("validation_duration_ms".to_string(), duration.to_string()),
                ("tests_run".to_string(), test_results.len().to_string()),
            ]),
        };

        tracing::info!(
            "FIPS validation completed in {}ms, valid: {}, level: {:?}",
            duration,
            result.is_valid,
            result.level
        );

        Ok(result)
    }

    /// Generate validation certificate for successful validation.
    ///
    /// # Errors
    /// Returns an error if validation failed or no security level was achieved.
    pub fn generate_certificate(
        &self,
        result: &ValidationResult,
    ) -> Result<ValidationCertificate, LatticeArcError> {
        if !result.is_valid || result.level.is_none() {
            return Err(LatticeArcError::InvalidInput(
                "Validation failed or no security level achieved".to_string(),
            ));
        }

        let level =
            result.level.ok_or(LatticeArcError::InvalidInput("No security level".to_string()))?;

        Ok(ValidationCertificate {
            id: format!("fips-cert-{}", uuid::Uuid::new_v4()),
            module_name: "LatticeArc Core".to_string(),
            module_version: env!("CARGO_PKG_VERSION").to_string(),
            security_level: level,
            validation_date: result.timestamp,
            expiry_date: result.timestamp + chrono::Duration::days(365),
            lab_id: "latticearc-lab".to_string(),
            details: HashMap::from([
                ("validation_id".to_string(), result.validation_id.clone()),
                ("scope".to_string(), format!("{:?}", result.scope)),
                ("issues_found".to_string(), result.issues.len().to_string()),
            ]),
        })
    }

    /// Get remediation guidance for validation issues
    #[must_use]
    pub fn get_remediation_guidance(&self, result: &ValidationResult) -> Vec<String> {
        let mut guidance = Vec::new();

        for issue in &result.issues {
            guidance
                .push(format!("{} ({}): {}", issue.id, issue.requirement_ref, issue.remediation));
        }

        if guidance.is_empty() {
            guidance.push("No remediation required - all tests passed".to_string());
        }

        guidance
    }

    /// Validate cryptographic algorithms
    fn validate_algorithms(
        issues: &mut Vec<ValidationIssue>,
        test_results: &mut HashMap<String, TestResult>,
    ) -> Result<(), LatticeArcError> {
        // AES validation
        let aes_result = test_aes_algorithm()?;
        test_results.insert("aes_validation".to_string(), aes_result.clone());

        if !aes_result.passed {
            issues.push(ValidationIssue {
                id: "FIPS-AES-001".to_string(),
                description: "AES algorithm validation failed".to_string(),
                requirement_ref: "FIPS 197".to_string(),
                severity: IssueSeverity::Critical,
                affected_component: "AES implementation".to_string(),
                remediation: "Fix AES implementation to comply with FIPS 197".to_string(),
                evidence: aes_result.output,
            });
        }

        // SHA-3 validation
        let sha3_result = test_sha3_algorithm()?;
        test_results.insert("sha3_validation".to_string(), sha3_result.clone());

        if !sha3_result.passed {
            issues.push(ValidationIssue {
                id: "FIPS-SHA3-001".to_string(),
                description: "SHA-3 algorithm validation failed".to_string(),
                requirement_ref: "FIPS 202".to_string(),
                severity: IssueSeverity::Critical,
                affected_component: "SHA-3 implementation".to_string(),
                remediation: "Fix SHA-3 implementation to comply with FIPS 202".to_string(),
                evidence: sha3_result.output,
            });
        }

        // ML-KEM validation (FIPS 203)
        let mlkem_result = test_mlkem_algorithm()?;
        test_results.insert("mlkem_validation".to_string(), mlkem_result.clone());

        if !mlkem_result.passed {
            issues.push(ValidationIssue {
                id: "FIPS-MLKEM-001".to_string(),
                description: "ML-KEM algorithm validation failed".to_string(),
                requirement_ref: "FIPS 203".to_string(),
                severity: IssueSeverity::Critical,
                affected_component: "ML-KEM implementation".to_string(),
                remediation: "Fix ML-KEM implementation to comply with FIPS 203".to_string(),
                evidence: mlkem_result.output,
            });
        }

        Ok(())
    }

    /// Validate module interfaces
    fn validate_interfaces(
        issues: &mut Vec<ValidationIssue>,
        test_results: &mut HashMap<String, TestResult>,
    ) -> Result<(), LatticeArcError> {
        // Test API interfaces
        let api_result = test_api_interfaces()?;
        test_results.insert("api_interfaces".to_string(), api_result.clone());

        if !api_result.passed {
            issues.push(ValidationIssue {
                id: "FIPS-INT-001".to_string(),
                description: "API interface validation failed".to_string(),
                requirement_ref: "FIPS 140-3 Section 4".to_string(),
                severity: IssueSeverity::High,
                affected_component: "API interfaces".to_string(),
                remediation: "Ensure all API interfaces follow FIPS 140-3 requirements".to_string(),
                evidence: api_result.output,
            });
        }

        // Test key management interfaces
        let key_result = test_key_management()?;
        test_results.insert("key_management".to_string(), key_result.clone());

        if !key_result.passed {
            issues.push(ValidationIssue {
                id: "FIPS-INT-002".to_string(),
                description: "Key management interface validation failed".to_string(),
                requirement_ref: "FIPS 140-3 Section 4".to_string(),
                severity: IssueSeverity::Critical,
                affected_component: "Key management".to_string(),
                remediation: "Implement FIPS-compliant key management interfaces".to_string(),
                evidence: key_result.output,
            });
        }

        Ok(())
    }

    /// Validate security policy
    fn validate_security_policy(
        issues: &mut Vec<ValidationIssue>,
        test_results: &mut HashMap<String, TestResult>,
    ) -> Result<(), LatticeArcError> {
        // Test self-tests
        let selftest_result = test_self_tests()?;
        test_results.insert("self_tests".to_string(), selftest_result.clone());

        if !selftest_result.passed {
            issues.push(ValidationIssue {
                id: "FIPS-SP-001".to_string(),
                description: "Self-test validation failed".to_string(),
                requirement_ref: "FIPS 140-3 Section 7".to_string(),
                severity: IssueSeverity::Critical,
                affected_component: "Self-test mechanisms".to_string(),
                remediation: "Implement proper power-up and conditional self-tests".to_string(),
                evidence: selftest_result.output,
            });
        }

        // Test error handling
        let error_result = test_error_handling()?;
        test_results.insert("error_handling".to_string(), error_result.clone());

        if !error_result.passed {
            issues.push(ValidationIssue {
                id: "FIPS-SP-002".to_string(),
                description: "Error handling validation failed".to_string(),
                requirement_ref: "FIPS 140-3 Section 7".to_string(),
                severity: IssueSeverity::High,
                affected_component: "Error handling".to_string(),
                remediation: "Improve error handling to prevent information leakage".to_string(),
                evidence: error_result.output,
            });
        }

        Ok(())
    }

    /// Determine achievable FIPS security level based on test results and issues
    ///
    /// FIPS 140-3 Security Level Determination:
    /// - Level 1: Basic security requirements met, algorithm validation passed
    /// - Level 2: Tamper-evident features + all Level 1 requirements
    /// - Level 3: Tamper-resistant features + all Level 2 requirements
    /// - Level 4: Tamper-resistant + environmental failure protection + all Level 3 requirements
    fn determine_security_level(
        issues: &[ValidationIssue],
        test_results: &HashMap<String, TestResult>,
    ) -> Option<FIPSLevel> {
        let has_critical = issues.iter().any(|i| i.severity == IssueSeverity::Critical);
        let has_high = issues.iter().any(|i| i.severity == IssueSeverity::High);
        let has_medium = issues.iter().any(|i| i.severity == IssueSeverity::Medium);

        // All critical tests must pass for any FIPS level
        let all_algorithm_tests_passed = test_results.values().all(|r| r.passed);

        // Cannot achieve any FIPS level with critical issues
        if has_critical || !all_algorithm_tests_passed {
            return None;
        }

        // Level assessment based on issues and test results
        if has_high {
            // High severity issues limit to Level 1
            Some(FIPSLevel::Level1)
        } else if has_medium {
            // Medium severity issues limit to Level 2
            Some(FIPSLevel::Level2)
        } else {
            // All tests pass with no medium or high severity issues
            // Default to Level 2 as baseline (can be upgraded to Level 3/4 with additional tests)
            Some(FIPSLevel::Level2)
        }
    }

    // Public test methods for conditional self-tests

    /// Test AES algorithm (public wrapper for conditional self-tests).
    ///
    /// # Errors
    /// Returns an error if the AES algorithm test fails to execute.
    pub fn test_aes_algorithm(&self) -> Result<TestResult, LatticeArcError> {
        test_aes_algorithm()
    }

    /// Test SHA-3 algorithm (public wrapper for conditional self-tests).
    ///
    /// # Errors
    /// Returns an error if the SHA-3 algorithm test fails to execute.
    pub fn test_sha3_algorithm(&self) -> Result<TestResult, LatticeArcError> {
        test_sha3_algorithm()
    }

    /// Test ML-KEM algorithm (public wrapper for conditional self-tests).
    ///
    /// # Errors
    /// Returns an error if the ML-KEM algorithm test fails to execute.
    pub fn test_mlkem_algorithm(&self) -> Result<TestResult, LatticeArcError> {
        test_mlkem_algorithm()
    }

    /// Test self-tests (public wrapper for conditional self-tests).
    ///
    /// # Errors
    /// Returns an error if the self-tests fail to execute.
    pub fn test_self_tests(&self) -> Result<TestResult, LatticeArcError> {
        test_self_tests()
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)] // Tests use expect for simplicity
#[allow(clippy::print_stderr)] // Tests use eprintln for diagnostic output
mod tests {
    use super::*;

    #[test]
    fn test_fips_validator_creation() {
        let validator = FIPSValidator::new(ValidationScope::AlgorithmsOnly);
        assert_eq!(validator.scope, ValidationScope::AlgorithmsOnly);
    }

    #[test]
    fn test_module_validation() {
        let validator = FIPSValidator::new(ValidationScope::AlgorithmsOnly);
        let result = validator.validate_module().expect("Validation should succeed");

        // Debug output if validation fails
        if !result.is_valid {
            eprintln!("Validation failed with issues:");
            for issue in &result.issues {
                eprintln!("  - {} ({:?}): {}", issue.id, issue.severity, issue.description);
                eprintln!("    Evidence: {}", issue.evidence);
            }
            for (name, test_result) in &result.test_results {
                if !test_result.passed {
                    eprintln!("  Test '{}' failed:", name);
                    eprintln!("    Output: {}", test_result.output);
                    if let Some(ref err) = test_result.error_message {
                        eprintln!("    Error: {}", err);
                    }
                }
            }
        }

        assert!(result.is_valid);
        assert!(result.level.is_some());
        assert!(!result.test_results.is_empty());
    }

    #[test]
    fn test_certificate_generation() {
        let validator = FIPSValidator::new(ValidationScope::AlgorithmsOnly);
        let result = validator.validate_module().expect("Validation should succeed");

        if result.is_valid() {
            let certificate = validator
                .generate_certificate(&result)
                .expect("Certificate generation should succeed");
            assert_eq!(certificate.module_name, "LatticeArc Core");
            assert!(certificate.security_level >= FIPSLevel::Level1);
        }
    }

    #[test]
    fn test_remediation_guidance() {
        let validator = FIPSValidator::new(ValidationScope::AlgorithmsOnly);
        let result = validator.validate_module().expect("Validation should succeed");
        let guidance = validator.get_remediation_guidance(&result);

        // Should have guidance even if no issues (confirmation message)
        assert!(!guidance.is_empty());
    }
}
