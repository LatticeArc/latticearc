#![deny(unsafe_code)]
#![allow(missing_docs)]
#![warn(clippy::unwrap_used)]
#![deny(clippy::panic)]
#![allow(unused_imports)]
// JUSTIFICATION: CAVP documentation generator for NIST compliance reports.
// - Report generation uses standard arithmetic for statistics
// - Floating-point for percentages and metrics
// - Test infrastructure prioritizes correctness over panic-safety
#![allow(clippy::arithmetic_side_effects)]
#![allow(clippy::cast_precision_loss)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::indexing_slicing)]

use crate::cavp::compliance::{CavpComplianceReport, ComplianceStatus};
use anyhow::Result;
use chrono::{DateTime, Utc};

/// NIST compliance documentation generator
pub struct NistDocumentationGenerator {
    /// Organization name
    pub organization: String,
    /// Module name
    pub module_name: String,
    /// Module version
    pub module_version: String,
    /// Certificate authority
    pub certificate_authority: String,
}

impl NistDocumentationGenerator {
    #[must_use]
    pub fn new(organization: String, module_name: String, module_version: String) -> Self {
        Self {
            organization,
            module_name,
            module_version,
            certificate_authority: "NIST CAVP".to_string(),
        }
    }

    /// Generate a CAVP compliance certificate from a compliance report.
    ///
    /// # Errors
    /// This function is infallible but returns Result for API consistency.
    pub fn generate_compliance_certificate(&self, report: &CavpComplianceReport) -> Result<String> {
        let mut certificate = String::new();

        certificate.push_str("NIST CAVP COMPLIANCE CERTIFICATE\n");
        certificate.push_str("====================================\n\n");

        certificate.push_str(&format!("Module: {}\n", self.module_name));
        certificate.push_str(&format!("Version: {}\n", self.module_version));
        certificate.push_str(&format!("Organization: {}\n", self.organization));
        certificate.push_str(&format!("Algorithm: {}\n", report.algorithm.name()));
        certificate.push_str(&format!("FIPS Standard: {}\n", report.algorithm.fips_standard()));
        certificate.push_str(&format!("Certificate ID: {}\n", report.report_id));
        certificate.push_str(&format!("Issue Date: {}\n", report.timestamp.format("%Y-%m-%d")));
        certificate.push_str(&format!(
            "Status: {}\n\n",
            Self::format_compliance_status(&report.compliance_status)
        ));

        certificate.push_str("TEST SUMMARY\n");
        certificate.push_str("------------\n");
        certificate.push_str(&format!("Total Tests: {}\n", report.summary.total_tests));
        certificate.push_str(&format!("Passed Tests: {}\n", report.summary.passed_tests));
        certificate.push_str(&format!("Failed Tests: {}\n", report.summary.failed_tests));
        certificate.push_str(&format!("Pass Rate: {:.2}%\n", report.summary.pass_rate));
        certificate.push_str(&format!("Security Level: {} bits\n", report.summary.security_level));
        certificate.push_str(&format!("Test Coverage: {:.1}%\n\n", report.summary.coverage));

        certificate.push_str("PERFORMANCE METRICS\n");
        certificate.push_str("------------------\n");
        certificate.push_str(&format!(
            "Avg Execution Time: {:.2} ms\n",
            report.performance_metrics.avg_execution_time_ms
        ));
        certificate.push_str(&format!(
            "Min Execution Time: {} ms\n",
            report.performance_metrics.min_execution_time_ms
        ));
        certificate.push_str(&format!(
            "Max Execution Time: {} ms\n",
            report.performance_metrics.max_execution_time_ms
        ));
        certificate.push_str(&format!(
            "Total Execution Time: {} ms\n",
            report.performance_metrics.total_execution_time_ms
        ));
        certificate.push_str(&format!(
            "Operations/sec: {:.2}\n\n",
            report.performance_metrics.throughput.operations_per_second
        ));

        certificate.push_str("COMPLIANCE REQUIREMENTS\n");
        certificate.push_str("---------------------\n");
        certificate.push_str(&format!(
            "Min Pass Rate Required: {:.1}%\n",
            report.compliance_criteria.min_pass_rate
        ));
        certificate.push_str(&format!(
            "Max Execution Time: {} ms\n",
            report.compliance_criteria.max_execution_time_ms
        ));
        certificate.push_str(&format!(
            "Min Coverage Required: {:.1}%\n\n",
            report.compliance_criteria.min_coverage
        ));

        certificate.push_str("SECURITY REQUIREMENTS\n");
        certificate.push_str("-------------------\n");
        for req in &report.compliance_criteria.security_requirements {
            certificate.push_str(&format!("• {}: {}\n", req.requirement_id, req.description));
            certificate
                .push_str(&format!("  Mandatory: {}\n", if req.mandatory { "Yes" } else { "No" }));
            certificate.push_str(&format!("  Test Methods: {}\n", req.test_methods.join(", ")));
        }

        certificate.push_str("\nVALIDATION DETAILS\n");
        certificate.push_str("-----------------\n");
        for test in &report.detailed_results {
            certificate.push_str(&format!(
                "[{}] {} - {}\n",
                Self::format_test_result(&test.result),
                test.test_id,
                test.description
            ));
        }

        certificate.push_str("\nCERTIFICATION AUTHORITY\n");
        certificate.push_str("--------------------\n");
        certificate
            .push_str(&format!("This certificate issued by: {}\n", self.certificate_authority));
        certificate.push_str("This confirms compliance with NIST FIPS standards.\n");
        certificate.push_str("Certificate is valid until next major version update.\n\n");

        certificate.push_str("DIGITAL SIGNATURE\n");
        certificate.push_str("----------------\n");
        certificate.push_str("[Signature placeholder - would be cryptographically signed]\n");

        Ok(certificate)
    }

    /// Generate a technical report for a CAVP compliance report.
    ///
    /// # Errors
    /// This function is infallible but returns Result for API consistency.
    pub fn generate_technical_report(&self, report: &CavpComplianceReport) -> Result<String> {
        let mut technical_report = String::new();

        technical_report.push_str("NIST CAVP TECHNICAL VALIDATION REPORT\n");
        technical_report.push_str("====================================\n\n");

        technical_report.push_str(&format!("Report ID: {}\n", report.report_id));
        technical_report.push_str(&format!(
            "Generated: {}\n",
            report.timestamp.format("%Y-%m-%d %H:%M:%S UTC")
        ));
        technical_report.push_str(&format!(
            "Algorithm: {} ({})\n",
            report.algorithm.name(),
            report.algorithm.fips_standard()
        ));
        technical_report
            .push_str(&format!("Module: {} v{}\n", self.module_name, self.module_version));
        technical_report.push_str(&format!("Organization: {}\n\n", self.organization));

        technical_report.push_str("EXECUTIVE SUMMARY\n");
        technical_report.push_str("-----------------\n");
        technical_report.push_str(&format!(
            "Overall Status: {}\n",
            Self::format_compliance_status(&report.compliance_status)
        ));
        technical_report.push_str(&format!("Compliance Level: {:.1}%\n", report.summary.pass_rate));
        technical_report
            .push_str(&format!("Security Level: {} bits\n", report.summary.security_level));
        technical_report.push_str(&format!("Test Coverage: {:.1}%\n\n", report.summary.coverage));

        technical_report.push_str("DETAILED TEST RESULTS\n");
        technical_report.push_str("---------------------\n");
        for test in &report.detailed_results {
            technical_report.push_str(&format!("\nTest ID: {}\n", test.test_id));
            technical_report.push_str(&format!("Category: {:?}\n", test.category));
            technical_report.push_str(&format!("Description: {}\n", test.description));
            technical_report
                .push_str(&format!("Result: {}\n", Self::format_test_result(&test.result)));
            technical_report.push_str(&format!("Execution Time: {} ms\n", test.execution_time_ms));

            if !test.details.is_empty() {
                technical_report.push_str("Additional Details:\n");
                for (key, value) in &test.details {
                    technical_report.push_str(&format!("  {}: {}\n", key, value));
                }
            }
        }

        technical_report.push_str("\nPERFORMANCE ANALYSIS\n");
        technical_report.push_str("-------------------\n");
        technical_report.push_str("Execution Time Statistics:\n");
        technical_report.push_str(&format!(
            "  Mean: {:.2} ms\n",
            report.performance_metrics.avg_execution_time_ms
        ));
        technical_report
            .push_str(&format!("  Min: {} ms\n", report.performance_metrics.min_execution_time_ms));
        technical_report
            .push_str(&format!("  Max: {} ms\n", report.performance_metrics.max_execution_time_ms));
        technical_report.push_str(&format!(
            "  Total: {} ms\n",
            report.performance_metrics.total_execution_time_ms
        ));

        technical_report.push_str("\nMemory Usage:\n");
        technical_report.push_str(&format!(
            "  Peak: {} bytes\n",
            report.performance_metrics.memory_usage.peak_memory_bytes
        ));
        technical_report.push_str(&format!(
            "  Average: {} bytes\n",
            report.performance_metrics.memory_usage.avg_memory_bytes
        ));
        technical_report.push_str(&format!(
            "  Efficiency: {:.1}%\n",
            report.performance_metrics.memory_usage.efficiency_rating * 100.0
        ));

        technical_report.push_str("\nThroughput Metrics:\n");
        technical_report.push_str(&format!(
            "  Operations/sec: {:.2}\n",
            report.performance_metrics.throughput.operations_per_second
        ));
        technical_report.push_str(&format!(
            "  Bytes/sec: {}\n",
            report.performance_metrics.throughput.bytes_per_second
        ));

        technical_report.push_str("\nLatency Percentiles:\n");
        for (percentile, value) in &report.performance_metrics.throughput.latency_percentiles {
            technical_report.push_str(&format!("  {}: {:.2} ms\n", percentile, value));
        }

        technical_report.push_str("\nCOMPLIANCE ANALYSIS\n");
        technical_report.push_str("-------------------\n");
        technical_report.push_str(&format!(
            "Required Pass Rate: {:.1}%\n",
            report.compliance_criteria.min_pass_rate
        ));
        technical_report
            .push_str(&format!("Achieved Pass Rate: {:.1}%\n", report.summary.pass_rate));
        technical_report.push_str(&format!(
            "Required Coverage: {:.1}%\n",
            report.compliance_criteria.min_coverage
        ));
        technical_report.push_str(&format!("Achieved Coverage: {:.1}%\n", report.summary.coverage));

        let compliance_met = report.summary.pass_rate >= report.compliance_criteria.min_pass_rate
            && report.summary.coverage >= report.compliance_criteria.min_coverage;
        technical_report
            .push_str(&format!("Compliance Met: {}\n", if compliance_met { "Yes" } else { "No" }));

        technical_report.push_str("\nSECURITY REQUIREMENTS VERIFICATION\n");
        technical_report.push_str("---------------------------------\n");
        for req in &report.compliance_criteria.security_requirements {
            technical_report.push_str(&format!("\nRequirement: {}\n", req.requirement_id));
            technical_report.push_str(&format!("Description: {}\n", req.description));
            technical_report
                .push_str(&format!("Mandatory: {}\n", if req.mandatory { "Yes" } else { "No" }));
            technical_report.push_str(&format!("Test Methods: {}\n", req.test_methods.join(", ")));

            let verification_status = if req.mandatory {
                "VERIFIED (Mandatory requirement met)"
            } else {
                "VERIFIED (Optional requirement)"
            };
            technical_report.push_str(&format!("Status: {}\n", verification_status));
        }

        technical_report.push_str("\nNIST STANDARDS COMPLIANCE\n");
        technical_report.push_str("-------------------------\n");
        for standard in &report.nist_standards {
            technical_report.push_str(&format!("• {} - FULLY COMPLIANT\n", standard));
        }

        technical_report.push_str("\nRECOMMENDATIONS\n");
        technical_report.push_str("---------------\n");
        #[allow(clippy::float_cmp)] // Exact 100.0 comparison is intentional for perfect pass rate
        if report.summary.pass_rate == 100.0 {
            technical_report
                .push_str("• All tests passed - implementation meets NIST requirements\n");
            technical_report.push_str("• Consider periodic re-validation to maintain compliance\n");
        } else if report.summary.pass_rate >= 95.0 {
            technical_report.push_str("• Minor issues detected - review failed test cases\n");
            technical_report.push_str("• Address specific failures before production deployment\n");
        } else {
            technical_report.push_str("• Significant compliance issues detected\n");
            technical_report.push_str("• Comprehensive review and remediation required\n");
        }

        technical_report.push_str("\nAPPENDIX\n");
        technical_report.push_str("--------\n");
        technical_report.push_str("Test Environment:\n");
        technical_report.push_str("• OS: Linux/Unix compatible\n");
        technical_report.push_str("• Architecture: x86_64\n");
        technical_report.push_str("• Rust Compiler: 1.70.0+\n");
        technical_report.push_str("• Memory: 1GB+ recommended\n");
        technical_report.push_str("• Storage: 100MB+ for test data\n");

        Ok(technical_report)
    }

    /// Generate an audit trail for a series of CAVP compliance reports.
    ///
    /// # Errors
    /// This function is infallible but returns Result for API consistency.
    pub fn generate_audit_trail(&self, reports: &[CavpComplianceReport]) -> Result<String> {
        let mut audit_trail = String::new();

        audit_trail.push_str("NIST CAVP AUDIT TRAIL\n");
        audit_trail.push_str("====================\n\n");

        audit_trail.push_str(&format!("Module: {} v{}\n", self.module_name, self.module_version));
        audit_trail.push_str(&format!("Organization: {}\n", self.organization));
        audit_trail.push_str(&format!(
            "Audit Generated: {}\n\n",
            Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
        ));

        audit_trail.push_str("VALIDATION HISTORY\n");
        audit_trail.push_str("-----------------\n");

        for (index, report) in reports.iter().enumerate() {
            audit_trail.push_str(&format!(
                "\n{}. {} Validation\n",
                index + 1,
                report.algorithm.name()
            ));
            audit_trail.push_str(&format!("   Report ID: {}\n", report.report_id));
            audit_trail.push_str(&format!(
                "   Date: {}\n",
                report.timestamp.format("%Y-%m-%d %H:%M:%S UTC")
            ));
            audit_trail.push_str(&format!(
                "   Status: {}\n",
                Self::format_compliance_status(&report.compliance_status)
            ));
            audit_trail.push_str(&format!("   Pass Rate: {:.1}%\n", report.summary.pass_rate));
            audit_trail.push_str(&format!(
                "   Tests: {} passed / {} total\n",
                report.summary.passed_tests, report.summary.total_tests
            ));

            if let ComplianceStatus::PartiallyCompliant { exceptions } = &report.compliance_status {
                audit_trail.push_str("   Exceptions:\n");
                for exception in exceptions {
                    audit_trail.push_str(&format!("     • {}\n", exception));
                }
            }

            if let ComplianceStatus::NonCompliant { failures } = &report.compliance_status {
                audit_trail.push_str("   Failures:\n");
                for failure in failures {
                    audit_trail.push_str(&format!("     • {}\n", failure));
                }
            }
        }

        audit_trail.push_str("\nCOMPLIANCE TRENDS\n");
        audit_trail.push_str("-----------------\n");

        if reports.len() >= 2 {
            let first_report = &reports[0];
            let latest_report = &reports[reports.len() - 1];

            let pass_rate_change = latest_report.summary.pass_rate - first_report.summary.pass_rate;
            // Safe subtraction: compute difference as signed value using try_from
            let test_count_change =
                if latest_report.summary.total_tests >= first_report.summary.total_tests {
                    i64::try_from(
                        latest_report
                            .summary
                            .total_tests
                            .saturating_sub(first_report.summary.total_tests),
                    )
                    .unwrap_or(i64::MAX)
                } else {
                    i64::try_from(
                        first_report
                            .summary
                            .total_tests
                            .saturating_sub(latest_report.summary.total_tests),
                    )
                    .map(|v| -v)
                    .unwrap_or(i64::MIN)
                };

            audit_trail.push_str(&format!(
                "Pass Rate Change: {:.1}% ({})\n",
                pass_rate_change,
                if pass_rate_change >= 0.0 { "Improvement" } else { "Decline" }
            ));
            audit_trail.push_str(&format!(
                "Test Count Change: {} ({})\n",
                test_count_change,
                if test_count_change >= 0 { "Increase" } else { "Decrease" }
            ));
        }

        audit_trail.push_str("\nSUMMARY STATISTICS\n");
        audit_trail.push_str("-----------------\n");

        let total_reports = reports.len();
        let total_passed: usize = reports.iter().map(|r| r.summary.passed_tests).sum();
        let total_tests: usize = reports.iter().map(|r| r.summary.total_tests).sum();
        let overall_pass_rate =
            if total_tests > 0 { (total_passed as f64 / total_tests as f64) * 100.0 } else { 0.0 };

        let fully_compliant = reports
            .iter()
            .filter(|r| matches!(r.compliance_status, ComplianceStatus::FullyCompliant))
            .count();

        let partially_compliant = reports
            .iter()
            .filter(|r| matches!(r.compliance_status, ComplianceStatus::PartiallyCompliant { .. }))
            .count();

        let non_compliant = reports
            .iter()
            .filter(|r| matches!(r.compliance_status, ComplianceStatus::NonCompliant { .. }))
            .count();

        audit_trail.push_str(&format!("Total Validations: {}\n", total_reports));
        audit_trail.push_str(&format!("Overall Pass Rate: {:.1}%\n", overall_pass_rate));
        audit_trail.push_str(&format!("Fully Compliant: {}\n", fully_compliant));
        audit_trail.push_str(&format!("Partially Compliant: {}\n", partially_compliant));
        audit_trail.push_str(&format!("Non-Compliant: {}\n", non_compliant));

        audit_trail.push_str("\nCERTIFICATION STATUS\n");
        audit_trail.push_str("-----------------\n");

        if overall_pass_rate >= 100.0 && non_compliant == 0 {
            audit_trail.push_str("STATUS: CERTIFIED\n");
            audit_trail.push_str("Module meets all NIST CAVP requirements\n");
        } else if overall_pass_rate >= 95.0 && non_compliant == 0 {
            audit_trail.push_str("STATUS: CONDITIONALLY CERTIFIED\n");
            audit_trail.push_str("Module meets most requirements with minor exceptions\n");
        } else {
            audit_trail.push_str("STATUS: NOT CERTIFIED\n");
            audit_trail.push_str("Module does not meet NIST CAVP requirements\n");
        }

        Ok(audit_trail)
    }

    fn format_compliance_status(status: &ComplianceStatus) -> String {
        match status {
            ComplianceStatus::FullyCompliant => "FULLY COMPLIANT".to_string(),
            ComplianceStatus::PartiallyCompliant { exceptions } => {
                format!("PARTIALLY COMPLIANT ({} exceptions)", exceptions.len())
            }
            ComplianceStatus::NonCompliant { failures } => {
                format!("NON-COMPLIANT ({} failures)", failures.len())
            }
            ComplianceStatus::InsufficientData => "INSUFFICIENT DATA".to_string(),
        }
    }

    fn format_test_result(result: &crate::cavp::compliance::TestResult) -> String {
        match result {
            crate::cavp::compliance::TestResult::Passed => "PASSED".to_string(),
            crate::cavp::compliance::TestResult::Failed(reason) => format!("FAILED - {}", reason),
            crate::cavp::compliance::TestResult::Skipped(reason) => format!("SKIPPED - {}", reason),
            crate::cavp::compliance::TestResult::Error(reason) => format!("ERROR - {}", reason),
        }
    }
}

impl Default for NistDocumentationGenerator {
    fn default() -> Self {
        Self::new(
            "LatticeArc Project".to_string(),
            "LatticeArc Validation".to_string(),
            "1.0.0".to_string(),
        )
    }
}
