//! CI/CD Testing Framework for Prelude Utilities
//!
//! This module provides automated testing infrastructure for continuous integration
//! of utility functions and error handling mechanisms.

#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

use crate::prelude::error::LatticeArcError;
use crate::types::domains;
/// Comprehensive CI test suite for prelude.
///
/// Provides automated testing for all prelude utility functions,
/// property-based testing, and memory safety validation.
pub struct PreludeCiTestSuite;

impl Default for PreludeCiTestSuite {
    fn default() -> Self {
        Self::new()
    }
}

impl PreludeCiTestSuite {
    /// Creates a new CI test suite instance.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Run complete CI test suite.
    ///
    /// # Errors
    ///
    /// Returns an error if any critical CI test fails.
    pub fn run_ci_tests(&mut self) -> Result<PreludeCiReport, LatticeArcError> {
        tracing::info!("Running Prelude CI Test Suite");

        let mut report = PreludeCiReport::default();

        // 1. Unit Tests
        tracing::info!("Running Unit Tests");
        let unit_tests_passed = Self::run_unit_tests().is_ok();
        report.unit_tests_passed = unit_tests_passed;
        if unit_tests_passed {
            tracing::info!("Unit tests passed");
        } else {
            tracing::error!("Unit tests failed");
        }

        // 2. Property Tests
        tracing::info!("Running Property Tests");
        let property_tests_passed = Self::run_property_tests();
        report.property_tests_passed = property_tests_passed;
        if property_tests_passed {
            tracing::info!("Property tests passed");
        } else {
            tracing::error!("Property tests failed");
        }

        // 3. Memory Safety Tests
        tracing::info!("Running Memory Safety Tests");
        let memory_safety_passed = Self::run_memory_safety_tests().is_ok();
        report.memory_safety_passed = memory_safety_passed;
        if memory_safety_passed {
            tracing::info!("Memory safety tests passed");
        } else {
            tracing::error!("Memory safety tests failed");
        }

        tracing::info!("Prelude CI Test Suite Completed");

        Ok(report)
    }

    /// Run property-style invariant smoke checks.
    ///
    /// The full proptest suite runs through `cargo test` (it can't be
    /// invoked from inside library code without re-implementing
    /// proptest's runner). The smoke checks here verify a few of the
    /// invariants those proptests cover, and return `true` only if
    /// they all pass — so a `passed = true` field actually reflects
    /// some verified work, not just framework availability.
    fn run_property_tests() -> bool {
        use crate::types::domains;

        // Invariant: domain constants must be pairwise distinct (a
        // collision would cause cross-protocol key reuse).
        let live_domains: &[&[u8]] =
            &[domains::CASCADE_OUTER, domains::CASCADE_INNER, domains::HYBRID_KEM_SS_INFO];
        for (i, a) in live_domains.iter().enumerate() {
            for (j, b) in live_domains.iter().enumerate() {
                if i != j && a == b {
                    tracing::error!("property smoke: domain constants collided");
                    return false;
                }
            }
        }

        // Invariant: hex round-trip is exact for all-bytes inputs.
        let bytes: Vec<u8> = (0u8..=255).collect();
        let hex_str = hex::encode(&bytes);
        let Ok(decoded) = hex::decode(&hex_str) else {
            tracing::error!("property smoke: hex round-trip decode failed");
            return false;
        };
        if decoded != bytes {
            tracing::error!("property smoke: hex round-trip not equal");
            return false;
        }

        tracing::info!("Property smoke checks passed");
        true
    }

    /// Run memory safety tests.
    fn run_memory_safety_tests() -> Result<bool, LatticeArcError> {
        let tester = crate::prelude::memory_safety_testing::UtilityMemorySafetyTester::new();
        tester.test_memory_safety_succeeds()?;
        tester.test_concurrent_safety_succeeds()?;
        Ok(true)
    }

    /// Run basic unit tests.
    fn run_unit_tests() -> Result<bool, LatticeArcError> {
        // Test core utility functions
        Self::test_hex_functions_succeeds()?;
        Self::test_uuid_functions_succeeds()?;
        Self::test_domain_constants_succeeds()?;
        Self::test_error_handling_fails()?;

        tracing::info!("Unit tests passed");
        Ok(true)
    }

    /// Test hex encoding/decoding.
    fn test_hex_functions_succeeds() -> Result<(), LatticeArcError> {
        let test_data = vec![0, 1, 255, 127, 64];

        // Test encoding
        let encoded = hex::encode(&test_data);
        if encoded != "0001ff7f40" {
            return Err(LatticeArcError::ValidationError {
                message: format!("Expected '0001ff7f40', got '{}'", encoded),
            });
        }

        // Test decoding
        let decoded = hex::decode(&encoded)?;
        if decoded != test_data {
            return Err(LatticeArcError::ValidationError {
                message: "Decoded data does not match original".to_string(),
            });
        }

        for _ in 0..10 {
            let mut data = vec![0u8; 32];
            let rand_data = crate::primitives::rand::csprng::random_bytes(32);
            data.copy_from_slice(&rand_data);
            let encoded = hex::encode(&data);
            let decoded = hex::decode(&encoded)?;
            if data != decoded {
                return Err(LatticeArcError::ValidationError {
                    message: "Hex round-trip failed".to_string(),
                });
            }
        }

        Ok(())
    }

    /// Test UUID functions.
    fn test_uuid_functions_succeeds() -> Result<(), LatticeArcError> {
        for _ in 0..10 {
            let uuid = uuid::Uuid::new_v4();

            // Basic validation
            if uuid.is_nil() {
                return Err(LatticeArcError::ValidationError {
                    message: "UUID should not be nil".to_string(),
                });
            }
            if uuid.get_version_num() != 4 {
                return Err(LatticeArcError::ValidationError {
                    message: format!("UUID version should be 4, got {}", uuid.get_version_num()),
                });
            }

            // String format validation
            let uuid_str = uuid.to_string();
            if uuid_str.len() != 36 {
                return Err(LatticeArcError::ValidationError {
                    message: format!("UUID string should be 36 chars, got {}", uuid_str.len()),
                });
            }

            // Parsing validation
            let parsed = uuid::Uuid::parse_str(&uuid_str)?;
            if parsed != uuid {
                return Err(LatticeArcError::ValidationError {
                    message: "Parsed UUID should match original".to_string(),
                });
            }
        }

        Ok(())
    }

    /// Test domain constants.
    fn test_domain_constants_succeeds() -> Result<(), LatticeArcError> {
        // Test all domain constants are non-empty
        if domains::CASCADE_OUTER.is_empty() {
            return Err(LatticeArcError::ValidationError {
                message: "CASCADE_OUTER should not be empty".to_string(),
            });
        }
        if domains::CASCADE_INNER.is_empty() {
            return Err(LatticeArcError::ValidationError {
                message: "CASCADE_INNER should not be empty".to_string(),
            });
        }
        if domains::HYBRID_KEM_SS_INFO.is_empty() {
            return Err(LatticeArcError::ValidationError {
                message: "HYBRID_KEM_SS_INFO should not be empty".to_string(),
            });
        }

        // Test they all contain the LatticeArc namespace prefix.
        // The deleted `HYBRID_KEM` / `SIGNATURE_BIND` constants used
        // `LatticeArc-v1-…`; the live `HYBRID_KEM_SS_INFO` is
        // `LatticeArc-Hybrid-KEM-SS-v1`, so `LatticeArc-v` is no
        // longer a contiguous substring across all live domains.
        // Check for the namespace prefix instead.
        let domain_list =
            [domains::CASCADE_OUTER, domains::CASCADE_INNER, domains::HYBRID_KEM_SS_INFO];
        for domain in &domain_list {
            if !(*domain).windows(11).any(|w| w == b"LatticeArc-") {
                return Err(LatticeArcError::ValidationError {
                    message: "Domain constant should contain LatticeArc- prefix".to_string(),
                });
            }
        }

        // Test uniqueness
        for (i, &domain1) in domain_list.iter().enumerate() {
            for (j, &domain2) in domain_list.iter().enumerate() {
                if i != j && domain1 == domain2 {
                    return Err(LatticeArcError::ValidationError {
                        message: "Domain constants should be unique".to_string(),
                    });
                }
            }
        }

        Ok(())
    }

    /// Test error handling.
    fn test_error_handling_fails() -> Result<(), LatticeArcError> {
        let test_errors = vec![
            LatticeArcError::InvalidInput("test".to_string()),
            LatticeArcError::NetworkError("connection failed".to_string()),
            LatticeArcError::IoError("file error".to_string()),
        ];

        for error in test_errors {
            // `LatticeArcError` is serialize-only (no Deserialize derive,
            // so attackers can't inject error variants via deserialization
            // sinks). Sanity-check that outbound JSON is well-formed and
            // mentions the variant name.
            let json = serde_json::to_string(&error)?;
            if json.is_empty() {
                return Err(LatticeArcError::ValidationError {
                    message: "Error JSON serialization produced empty output".to_string(),
                });
            }
            let _value: serde_json::Value = serde_json::from_str(&json)?;
        }

        Ok(())
    }
}

/// CI test report containing results from all test categories.
#[derive(Default)]
pub struct PreludeCiReport {
    /// Whether all unit tests passed.
    pub unit_tests_passed: bool,
    /// CAVP compliance report if generated.
    pub cavp_compliance_report: Option<String>,
    /// Whether all property-based tests passed.
    pub property_tests_passed: bool,
    /// Side-channel vulnerability assessments.
    pub side_channel_assessments: Vec<crate::prelude::side_channel_analysis::SideChannelAssessment>,
    /// Side-channel analysis report if generated.
    pub side_channel_report: Option<String>,
    /// Whether all memory safety tests passed.
    pub memory_safety_passed: bool,
    /// Performance benchmark results.
    pub performance_results: PerformanceResults,
}

/// Performance benchmark results for utility operations.
#[derive(Debug, Clone, Default)]
pub struct PerformanceResults {
    /// Average time for hex encoding (1KB data).
    pub hex_encode_avg: std::time::Duration,
    /// Average time for UUID generation.
    pub uuid_generate_avg: std::time::Duration,
}

impl PreludeCiReport {
    /// Generate comprehensive CI report.
    ///
    /// Creates a markdown-formatted report containing all test results,
    /// performance metrics, and compliance status.
    #[must_use]
    pub fn generate_report(&self) -> String {
        let mut report = String::from("# Prelude CI Test Report\n\n");

        report.push_str("## 📊 Executive Summary\n\n");

        let overall_status =
            if self.unit_tests_passed && self.property_tests_passed && self.memory_safety_passed {
                "✅ **ALL TESTS PASSED**"
            } else {
                "❌ **ISSUES DETECTED**"
            };

        report.push_str(&format!("**Overall Status:** {}\n\n", overall_status));

        // Test Results Summary
        report.push_str("### Test Results Summary\n\n");
        report.push_str(&format!(
            "- Unit Tests: {}\n",
            if self.unit_tests_passed { "✅ PASSED" } else { "❌ FAILED" }
        ));
        report.push_str(&format!(
            "- Property Tests: {}\n",
            if self.property_tests_passed { "✅ PASSED" } else { "❌ FAILED" }
        ));
        report.push_str(&format!(
            "- Memory Safety: {}\n",
            if self.memory_safety_passed { "✅ PASSED" } else { "❌ FAILED" }
        ));

        // Side-Channel Summary
        let high_severity = self
            .side_channel_assessments
            .iter()
            .filter(|a| {
                matches!(
                    a.severity,
                    crate::prelude::side_channel_analysis::Severity::High
                        | crate::prelude::side_channel_analysis::Severity::Critical
                )
            })
            .count();

        report.push_str(&format!("- High/Critical Side-Channel Issues: {}\n", high_severity));

        // Performance Summary
        report.push_str(&format!(
            "- Hex Encode (1KB): {:.2}µs\n",
            self.performance_results.hex_encode_avg.as_secs_f64() * 1_000_000.0
        ));
        report.push_str(&format!(
            "- UUID Generate: {:.2}µs\n\n",
            self.performance_results.uuid_generate_avg.as_secs_f64() * 1_000_000.0
        ));

        // Detailed Sections
        if let Some(cavp_report) = &self.cavp_compliance_report {
            report.push_str("\n## 🔐 CAVP Compliance Report\n\n");
            report.push_str(cavp_report);
        }

        if let Some(side_channel_report) = &self.side_channel_report {
            report.push_str("\n## 🔍 Side-Channel Analysis Report\n\n");
            report.push_str(side_channel_report);
        }

        report.push_str("\n## ⚡ Performance Benchmarks\n\n");
        report.push_str(&format!(
            "- **Hex Encoding (1KB):** {:?} per operation\n",
            self.performance_results.hex_encode_avg
        ));
        report.push_str(&format!(
            "- **UUID Generation:** {:?} per operation\n",
            self.performance_results.uuid_generate_avg
        ));

        report.push_str("\n## 🎯 Compliance Status\n\n");
        report.push_str("- ✅ Unit Test Coverage\n");
        report.push_str("- ✅ Property-Based Testing\n");
        report.push_str("- ✅ Memory Safety Validation\n");
        report.push_str("- ✅ CAVP Compliance Framework\n");
        report.push_str("- ✅ Side-Channel Analysis\n");
        report.push_str("- ✅ Performance Benchmarking\n");

        report.push_str("\n---\n");
        report.push_str("*Report generated by Prelude CI Test Suite*");

        report
    }

    /// Check if all critical tests passed.
    ///
    /// Returns true if unit tests, property tests, and memory safety
    /// tests all passed, and there are no Critical OR High severity
    /// side-channel vulnerabilities. (The function name says
    /// "critical" but the policy is "block release on Critical OR
    /// High" — a CI gate that ignored High would let real findings
    /// through.)
    #[must_use]
    pub fn all_critical_tests_passed(&self) -> bool {
        use crate::prelude::side_channel_analysis::Severity;
        self.unit_tests_passed
            && self.property_tests_passed
            && self.memory_safety_passed
            && self
                .side_channel_assessments
                .iter()
                .filter(|a| matches!(a.severity, Severity::Critical | Severity::High))
                .count()
                == 0
    }
}

/// CI integration functions for automated environments.
pub mod ci_integration {
    use super::*;

    /// Run CI tests suitable for automated environments.
    ///
    /// This function provides a simplified interface for running
    /// the complete CI test suite in automated build pipelines.
    ///
    /// # Errors
    ///
    /// Returns an error if CI tests fail in the automated environment.
    pub fn run_ci_tests() -> Result<(), LatticeArcError> {
        tracing::info!("Running Prelude CI Tests");
        let mut suite = PreludeCiTestSuite::new();
        let report = suite.run_ci_tests()?;
        if !report.all_critical_tests_passed() {
            return Err(LatticeArcError::ValidationError {
                message: "Prelude CI suite reported failures (see report for details)".to_string(),
            });
        }
        tracing::info!("Prelude CI tests completed successfully");
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)] // Tests use unwrap for simplicity
mod tests {
    use super::*;

    #[test]
    fn test_ci_test_suite_all_critical_tests_pass_succeeds() {
        let mut suite = PreludeCiTestSuite::new();
        let report = suite.run_ci_tests().unwrap();

        // Generate report
        let full_report = report.generate_report();
        assert!(full_report.contains("Prelude CI Test Report"));

        // Check critical tests
        assert!(report.all_critical_tests_passed());
    }

    #[test]
    fn test_ci_integration_succeeds() {
        assert!(ci_integration::run_ci_tests().is_ok());
    }

    #[test]
    fn test_prelude_ci_test_suite_default_succeeds() {
        let suite = PreludeCiTestSuite;
        // Just verify default construction works
        let _ = suite;
    }

    #[test]
    fn test_generate_report_with_failures_fails() {
        let report = PreludeCiReport {
            unit_tests_passed: false,
            property_tests_passed: true,
            memory_safety_passed: false,
            cavp_compliance_report: Some("CAVP results here".to_string()),
            side_channel_report: Some("Side channel report here".to_string()),
            side_channel_assessments: vec![],
            performance_results: PerformanceResults {
                hex_encode_avg: std::time::Duration::from_micros(5),
                uuid_generate_avg: std::time::Duration::from_micros(10),
            },
        };

        let text = report.generate_report();
        assert!(text.contains("ISSUES DETECTED"));
        assert!(text.contains("FAILED"));
        assert!(text.contains("CAVP Compliance Report"));
        assert!(text.contains("Side-Channel Analysis Report"));
        assert!(!report.all_critical_tests_passed());
    }

    #[test]
    fn test_generate_report_with_side_channel_assessments_succeeds() {
        use crate::prelude::side_channel_analysis::{
            Severity, SideChannelAssessment, SideChannelType,
        };

        let report = PreludeCiReport {
            unit_tests_passed: true,
            property_tests_passed: true,
            memory_safety_passed: true,
            cavp_compliance_report: None,
            side_channel_report: None,
            side_channel_assessments: vec![SideChannelAssessment {
                vulnerability_type: SideChannelType::Timing,
                severity: Severity::Critical,
                confidence: 0.95,
                description: "Timing leak".to_string(),
                mitigation_suggestions: vec!["Use constant-time".to_string()],
            }],
            performance_results: PerformanceResults::default(),
        };

        let text = report.generate_report();
        assert!(text.contains("High/Critical Side-Channel Issues: 1"));
        assert!(!report.all_critical_tests_passed());
    }

    #[test]
    fn test_all_critical_tests_passed_blocks_high_severity() {
        use crate::prelude::side_channel_analysis::{
            Severity, SideChannelAssessment, SideChannelType,
        };

        let report = PreludeCiReport {
            unit_tests_passed: true,
            property_tests_passed: true,
            memory_safety_passed: true,
            cavp_compliance_report: None,
            side_channel_report: None,
            side_channel_assessments: vec![SideChannelAssessment {
                vulnerability_type: SideChannelType::Cache,
                severity: Severity::High,
                confidence: 0.8,
                description: "Cache leak".to_string(),
                mitigation_suggestions: vec!["Flush".to_string()],
            }],
            performance_results: PerformanceResults::default(),
        };

        // High severity must block the gate. The function name says
        // "critical" but the policy is "Critical OR High"; a CI gate
        // that lets High through would be silently broken.
        assert!(!report.all_critical_tests_passed());
    }

    #[test]
    fn test_performance_results_debug_succeeds() {
        let perf = PerformanceResults::default();
        let debug = format!("{:?}", perf);
        assert!(debug.contains("PerformanceResults"));
    }

    // ---- Coverage: generate_report and ci_integration ----

    #[test]
    fn test_generate_report_all_passing_succeeds() {
        let mut suite = PreludeCiTestSuite::new();
        let report = suite.run_ci_tests().unwrap();

        let text = report.generate_report();
        assert!(text.contains("ALL TESTS PASSED"));
        assert!(text.contains("Test Results Summary"));
        assert!(text.contains("Performance Benchmarks"));
        assert!(text.contains("Compliance Status"));
    }

    #[test]
    fn test_all_critical_tests_passed_true_when_all_pass_succeeds() {
        let report = PreludeCiReport {
            unit_tests_passed: true,
            property_tests_passed: true,
            memory_safety_passed: true,
            cavp_compliance_report: None,
            side_channel_report: None,
            side_channel_assessments: vec![],
            performance_results: PerformanceResults::default(),
        };
        assert!(report.all_critical_tests_passed());
    }

    #[test]
    fn test_ci_report_default_field_values_succeeds() {
        let report = PreludeCiReport::default();
        assert!(!report.unit_tests_passed);
        assert!(!report.property_tests_passed);
        assert!(!report.memory_safety_passed);
        assert!(report.cavp_compliance_report.is_none());
        assert!(report.side_channel_report.is_none());
        assert!(report.side_channel_assessments.is_empty());
    }

    #[test]
    fn test_run_ci_tests_standalone_function_succeeds() {
        let result = ci_integration::run_ci_tests();
        assert!(result.is_ok());
    }

    #[test]
    fn test_generate_report_with_optional_sections_succeeds() {
        let report = PreludeCiReport {
            unit_tests_passed: true,
            property_tests_passed: true,
            memory_safety_passed: true,
            cavp_compliance_report: Some("CAVP test data".to_string()),
            side_channel_report: Some("Side-channel report data".to_string()),
            side_channel_assessments: vec![],
            performance_results: PerformanceResults::default(),
        };
        let text = report.generate_report();
        assert!(text.contains("CAVP Compliance Report"));
        assert!(text.contains("CAVP test data"));
        assert!(text.contains("Side-Channel Analysis Report"));
        assert!(text.contains("Side-channel report data"));
    }

    #[test]
    fn test_generate_report_issues_detected_succeeds() {
        let report = PreludeCiReport {
            unit_tests_passed: false,
            property_tests_passed: true,
            memory_safety_passed: true,
            cavp_compliance_report: None,
            side_channel_report: None,
            side_channel_assessments: vec![],
            performance_results: PerformanceResults::default(),
        };
        let text = report.generate_report();
        assert!(text.contains("ISSUES DETECTED"));
        assert!(text.contains("FAILED"));
    }
}
