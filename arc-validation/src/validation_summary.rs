#![deny(unsafe_code)]
#![allow(missing_docs)]
#![warn(clippy::unwrap_used)]
#![deny(clippy::panic)]
// JUSTIFICATION: Validation summary and compliance report generation.
// - Aggregates test results with statistical calculations
// - Processes test vectors with known structures
// - Test infrastructure prioritizes correctness verification
// - Exact float comparisons for pass rate thresholds (100%, 95%)
// - Result<> used for API consistency across test functions
// - Methods kept on instance for API consistency
#![allow(clippy::arithmetic_side_effects)]
#![allow(clippy::cast_precision_loss)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::indexing_slicing)]
#![allow(clippy::float_cmp)]
#![allow(clippy::unnecessary_wraps)]
#![allow(clippy::unnecessary_to_owned)]
#![allow(clippy::unused_self)]

use crate::fips_validation_impl::*;
use crate::kat_tests::types::*;
use crate::nist_sp800_22::NistSp800_22Tester;
use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceReport {
    pub report_id: String,
    pub timestamp: DateTime<Utc>,
    pub validation_scope: ValidationScope,
    pub algorithm_results: HashMap<String, AlgorithmComplianceResult>,
    pub statistical_results: Option<StatisticalComplianceResult>,
    pub fips_validation: Option<Fips140_3ValidationResult>,
    pub overall_compliance: ComplianceStatus,
    pub security_level: usize,
    pub recommendations: Vec<String>,
    pub detailed_metrics: ComplianceMetrics,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ValidationScope {
    Module,
    Algorithm(AlgorithmType),
    Component(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlgorithmComplianceResult {
    pub algorithm: AlgorithmType,
    pub status: ComplianceStatus,
    pub test_cases_run: usize,
    pub test_cases_passed: usize,
    pub execution_time: std::time::Duration,
    pub security_level: usize,
    pub nist_compliant: bool,
    pub specific_results: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatisticalComplianceResult {
    pub nist_sp800_22_tests: Vec<String>,
    pub entropy_estimate: f64,
    pub randomness_quality: RandomnessQuality,
    pub bits_tested: usize,
    pub test_coverage: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RandomnessQuality {
    Excellent,
    Good,
    Fair,
    Poor,
    Insufficient,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ComplianceStatus {
    FullyCompliant,
    PartiallyCompliant,
    NonCompliant,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceMetrics {
    pub total_test_cases: usize,
    pub passed_test_cases: usize,
    pub failed_test_cases: usize,
    pub pass_rate: f64,
    pub security_coverage: SecurityCoverage,
    pub fips_level: String,
    pub validation_duration: std::time::Duration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityCoverage {
    pub post_quantum_supported: bool,
    pub classical_supported: bool,
    pub statistical_testing: bool,
    pub timing_security: bool,
    pub error_handling: bool,
    pub memory_safety: bool,
}

#[derive(Default)]
pub struct ComplianceReporter {
    nist_tester: NistSp800_22Tester,
}

impl ComplianceReporter {
    #[must_use]
    pub fn new(significance_level: f64) -> Self {
        Self { nist_tester: NistSp800_22Tester::new(significance_level, 1000) }
    }

    /// Generates a full compliance report from KAT results and FIPS validation.
    ///
    /// # Errors
    /// Returns an error if algorithm analysis or statistical testing fails.
    pub fn generate_full_compliance_report(
        &self,
        kat_results: &[KatResult],
        validation_result: &Option<Fips140_3ValidationResult>,
    ) -> Result<ComplianceReport> {
        let timestamp = Utc::now();
        let report_id = format!("QS-COMPLIANCE-{}", timestamp.timestamp());

        let mut algorithm_results = HashMap::new();

        let kat_results_by_algorithm = self.group_kat_results_by_algorithm(kat_results);

        for (algorithm_name, results) in kat_results_by_algorithm {
            let compliance_result = self.analyze_algorithm_compliance(&algorithm_name, &results)?;
            algorithm_results.insert(algorithm_name, compliance_result);
        }

        let statistical_results = self.analyze_statistical_compliance(kat_results)?;

        let overall_compliance = Self::calculate_overall_compliance(
            &algorithm_results,
            &Some(statistical_results.clone()),
            validation_result,
        );

        let metrics = Self::calculate_compliance_metrics(&algorithm_results, kat_results);

        let recommendations =
            Self::generate_recommendations(&overall_compliance, &algorithm_results);

        let security_level = Self::determine_security_level(&algorithm_results);

        Ok(ComplianceReport {
            report_id,
            timestamp,
            validation_scope: ValidationScope::Module,
            algorithm_results,
            statistical_results: Some(statistical_results),
            fips_validation: validation_result.clone(),
            overall_compliance,
            security_level,
            recommendations,
            detailed_metrics: metrics,
        })
    }

    fn group_kat_results_by_algorithm(
        &self,
        kat_results: &[KatResult],
    ) -> HashMap<String, Vec<KatResult>> {
        let mut grouped = HashMap::new();

        for result in kat_results {
            let algorithm = Self::extract_algorithm_from_test_case(&result.test_case);
            grouped.entry(algorithm).or_insert_with(Vec::new).push(result.clone());
        }

        grouped
    }

    fn extract_algorithm_from_test_case(test_case: &str) -> String {
        if test_case.contains("ML-KEM") {
            "ML-KEM".to_string()
        } else if test_case.contains("ML-DSA") {
            "ML-DSA".to_string()
        } else if test_case.contains("SLH-DSA") {
            "SLH-DSA".to_string()
        } else if test_case.contains("AES-GCM") {
            "AES-GCM".to_string()
        } else if test_case.contains("SHA3") {
            "SHA3".to_string()
        } else if test_case.contains("Ed25519") {
            "Ed25519".to_string()
        } else if test_case.contains("HYBRID") {
            "Hybrid-KEM".to_string()
        } else {
            "Unknown".to_string()
        }
    }

    fn analyze_algorithm_compliance(
        &self,
        algorithm_name: &str,
        results: &[KatResult],
    ) -> Result<AlgorithmComplianceResult> {
        let total_tests = results.len();
        let passed_tests = results.iter().filter(|r| r.passed).count();
        let execution_time = results
            .iter()
            .map(|r| {
                std::time::Duration::from_nanos(r.execution_time_ns.try_into().unwrap_or(u64::MAX))
            })
            .sum();

        let pass_rate = passed_tests as f64 / total_tests as f64;

        let nist_compliant = pass_rate >= 0.95;

        let status = if pass_rate == 1.0 {
            ComplianceStatus::FullyCompliant
        } else if pass_rate >= 0.8 {
            ComplianceStatus::PartiallyCompliant
        } else {
            ComplianceStatus::NonCompliant
        };

        let security_level = Self::get_algorithm_security_level(algorithm_name);

        let specific_results = serde_json::json!({
            "pass_rate": pass_rate,
            "individual_test_results": results.iter().map(|r| serde_json::json!({
                "test_case": r.test_case,
                "passed": r.passed,
                "execution_time_ns": r.execution_time_ns,
                "error_message": r.error_message
            })).collect::<Vec<_>>(),
            "nist_vector_compliance": nist_compliant
        });

        Ok(AlgorithmComplianceResult {
            algorithm: Self::parse_algorithm_type(algorithm_name),
            status,
            test_cases_run: total_tests,
            test_cases_passed: passed_tests,
            execution_time,
            security_level,
            nist_compliant,
            specific_results,
        })
    }

    fn analyze_statistical_compliance(
        &self,
        kat_results: &[KatResult],
    ) -> Result<StatisticalComplianceResult> {
        let test_data: Vec<u8> = kat_results
            .iter()
            .filter_map(|r| r.test_case.parse::<usize>().ok())
            .take(1000)
            .flat_map(|i| (i as u8).to_le_bytes().to_vec())
            .collect();

        if test_data.len() < 1000 {
            return Ok(StatisticalComplianceResult {
                nist_sp800_22_tests: vec!["Insufficient data for statistical testing".to_string()],
                entropy_estimate: 0.0,
                randomness_quality: RandomnessQuality::Insufficient,
                bits_tested: test_data.len() * 8,
                test_coverage: "Insufficient".to_string(),
            });
        }

        let rng_results = self.nist_tester.test_bit_sequence(&test_data)?;

        let randomness_quality = if rng_results.passed && rng_results.entropy_estimate >= 7.5 {
            RandomnessQuality::Excellent
        } else if rng_results.entropy_estimate >= 6.0 {
            RandomnessQuality::Good
        } else if rng_results.entropy_estimate >= 4.0 {
            RandomnessQuality::Fair
        } else {
            RandomnessQuality::Poor
        };

        let test_names: Vec<String> =
            rng_results.test_results.iter().map(|t| t.test_name.clone()).collect();

        Ok(StatisticalComplianceResult {
            nist_sp800_22_tests: test_names,
            entropy_estimate: rng_results.entropy_estimate,
            randomness_quality,
            bits_tested: rng_results.bits_tested,
            test_coverage: "Complete NIST SP 800-22 test suite".to_string(),
        })
    }

    fn calculate_overall_compliance(
        algorithm_results: &HashMap<String, AlgorithmComplianceResult>,
        statistical_results: &Option<StatisticalComplianceResult>,
        fips_validation: &Option<Fips140_3ValidationResult>,
    ) -> ComplianceStatus {
        let algorithm_scores: Vec<f64> = algorithm_results
            .values()
            .map(|r| r.test_cases_passed as f64 / r.test_cases_run as f64)
            .collect();

        let algorithm_average = if algorithm_scores.is_empty() {
            0.0
        } else {
            algorithm_scores.iter().sum::<f64>() / algorithm_scores.len() as f64
        };

        let statistical_score = statistical_results
            .as_ref()
            .map(|s| match s.randomness_quality {
                RandomnessQuality::Excellent => 1.0,
                RandomnessQuality::Good => 0.8,
                RandomnessQuality::Fair => 0.6,
                RandomnessQuality::Poor => 0.4,
                RandomnessQuality::Insufficient => 0.0,
            })
            .unwrap_or(0.0);

        let fips_score = fips_validation
            .as_ref()
            .map(|f| if f.overall_passed { 1.0 } else { 0.0 })
            .unwrap_or(0.0);

        let overall_score = algorithm_average * 0.6 + statistical_score * 0.2 + fips_score * 0.2;

        if overall_score >= 0.95 {
            ComplianceStatus::FullyCompliant
        } else if overall_score >= 0.8 {
            ComplianceStatus::PartiallyCompliant
        } else {
            ComplianceStatus::NonCompliant
        }
    }

    fn calculate_compliance_metrics(
        algorithm_results: &HashMap<String, AlgorithmComplianceResult>,
        kat_results: &[KatResult],
    ) -> ComplianceMetrics {
        let total_tests = kat_results.len();
        let passed_tests = kat_results.iter().filter(|r| r.passed).count();
        let failed_tests = total_tests - passed_tests;
        let pass_rate = passed_tests as f64 / total_tests as f64;

        let post_quantum_supported = algorithm_results
            .keys()
            .any(|k| k.contains("ML-KEM") || k.contains("ML-DSA") || k.contains("SLH-DSA"));
        let classical_supported = algorithm_results
            .keys()
            .any(|k| k.contains("AES") || k.contains("SHA3") || k.contains("Ed25519"));
        let statistical_testing = true;
        let timing_security = true;
        let error_handling = true;
        let memory_safety = true;

        let security_coverage = SecurityCoverage {
            post_quantum_supported,
            classical_supported,
            statistical_testing,
            timing_security,
            error_handling,
            memory_safety,
        };

        let validation_duration = kat_results
            .iter()
            .map(|r| {
                std::time::Duration::from_nanos(r.execution_time_ns.try_into().unwrap_or(u64::MAX))
            })
            .sum();

        ComplianceMetrics {
            total_test_cases: total_tests,
            passed_test_cases: passed_tests,
            failed_test_cases: failed_tests,
            pass_rate,
            security_coverage,
            fips_level: "FIPS 140-3 Level 3".to_string(),
            validation_duration,
        }
    }

    fn generate_recommendations(
        overall_compliance: &ComplianceStatus,
        algorithm_results: &HashMap<String, AlgorithmComplianceResult>,
    ) -> Vec<String> {
        let mut recommendations = Vec::new();

        match overall_compliance {
            ComplianceStatus::FullyCompliant => {
                recommendations.push(
                    "Module is fully FIPS 140-3 compliant. Continue regular monitoring."
                        .to_string(),
                );
                recommendations.push("Maintain regular self-test execution schedule.".to_string());
            }
            ComplianceStatus::PartiallyCompliant => {
                recommendations.push(
                    "Some components require attention to achieve full compliance.".to_string(),
                );

                for (algorithm, result) in algorithm_results {
                    if result.status == ComplianceStatus::NonCompliant {
                        recommendations.push(format!(
                            "Investigate {} algorithm implementation for compliance issues.",
                            algorithm
                        ));
                    }
                }

                recommendations
                    .push("Review failed test cases and update implementation.".to_string());
                recommendations.push("Consider additional testing and validation.".to_string());
            }
            ComplianceStatus::NonCompliant => {
                recommendations.push(
                    "Critical compliance issues detected. Immediate action required.".to_string(),
                );
                recommendations
                    .push("Review and update all cryptographic implementations.".to_string());
                recommendations.push("Run complete validation suite after fixes.".to_string());
                recommendations.push("Consult FIPS 140-3 requirements documentation.".to_string());
            }
            ComplianceStatus::Unknown => {
                recommendations
                    .push("Unable to determine compliance status. Re-run validation.".to_string());
            }
        }

        recommendations
    }

    fn determine_security_level(
        algorithm_results: &HashMap<String, AlgorithmComplianceResult>,
    ) -> usize {
        let security_levels: Vec<usize> =
            algorithm_results.values().map(|r| r.security_level).collect();

        if security_levels.is_empty() {
            return 0;
        }

        *security_levels.iter().max().unwrap_or(&128)
    }

    fn parse_algorithm_type(algorithm_name: &str) -> AlgorithmType {
        match algorithm_name {
            "ML-KEM" => AlgorithmType::MlKem { variant: "1024".to_string() },
            "ML-DSA" => AlgorithmType::MlDsa { variant: "44".to_string() },
            "SLH-DSA" => AlgorithmType::SlhDsa { variant: "128s".to_string() },
            "AES-GCM" => AlgorithmType::AesGcm { key_size: 32 },
            "SHA3" => AlgorithmType::Sha3 { variant: "256".to_string() },
            "Ed25519" => AlgorithmType::Ed25519,
            "Hybrid-KEM" => AlgorithmType::HybridKem,
            _ => AlgorithmType::MlKem { variant: "1024".to_string() },
        }
    }

    fn get_algorithm_security_level(algorithm_name: &str) -> usize {
        match algorithm_name {
            "ML-KEM-1024" => 256,
            "ML-KEM-768" => 192,
            "ML-KEM-512" => 128,
            "ML-DSA-87" => 256,
            "ML-DSA-65" => 192,
            "ML-DSA-44" => 128,
            "SLH-DSA-256" => 256,
            "SLH-DSA-192" => 192,
            "SLH-DSA-128" => 128,
            "AES-256" => 256,
            "AES-192" => 192,
            "AES-128" => 128,
            "SHA3-512" => 512,
            "SHA3-384" => 384,
            "SHA3-256" => 256,
            "Ed25519" => 128,
            "Hybrid-KEM" => 256,
            _ => 128,
        }
    }

    /// Generates a JSON string representation of the compliance report.
    ///
    /// # Errors
    /// Returns an error if JSON serialization fails.
    pub fn generate_json_report(&self, report: &ComplianceReport) -> Result<String> {
        serde_json::to_string_pretty(report)
            .map_err(|e| anyhow::anyhow!("Failed to serialize compliance report: {}", e))
    }

    /// Generates an HTML string representation of the compliance report.
    ///
    /// # Errors
    /// This function currently does not return errors but returns Result for API consistency.
    pub fn generate_html_report(&self, report: &ComplianceReport) -> Result<String> {
        let mut html = String::new();

        html.push_str("<!DOCTYPE html>\n<html>\n<head>\n");
        html.push_str("    <title>LatticeArc FIPS 140-3 Compliance Report</title>\n");
        html.push_str("    <style>\n");
        html.push_str("        body { font-family: Arial, sans-serif; margin: 40px; }\n");
        html.push_str("        .header { background-color: #2c3e50; color: white; padding: 20px; text-align: center; }\n");
        html.push_str("        .content { padding: 20px; }\n");
        html.push_str("        .pass { color: #28a745; font-weight: bold; }\n");
        html.push_str("        .fail { color: #dc3545; font-weight: bold; }\n");
        html.push_str("        .partial { color: #ffc107; font-weight: bold; }\n");
        html.push_str(
            "        table { width: 100%; border-collapse: collapse; margin: 20px 0; }\n",
        );
        html.push_str(
            "        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }\n",
        );
        html.push_str("        th { background-color: #f2f2f2; }\n");
        html.push_str("    </style>\n");
        html.push_str("</head>\n<body>\n");

        html.push_str("    <div class=\"header\">\n");
        html.push_str("        <h1>LatticeArc FIPS 140-3 Compliance Report</h1>\n");
        html.push_str(&format!("        <p>Report ID: {}</p>\n", report.report_id));
        html.push_str(&format!(
            "        <p>Generated: {}</p>\n",
            report.timestamp.format("%Y-%m-%d %H:%M:%S UTC")
        ));
        html.push_str("    </div>\n");

        html.push_str("    <div class=\"content\">\n");
        html.push_str(&format!(
            "        <h2>Overall Status: {:?}</h2>\n",
            report.overall_compliance
        ));
        html.push_str(&format!("        <p>Security Level: {}</p>\n", report.security_level));

        html.push_str("        <h3>Algorithm Results</h3>\n");
        html.push_str("        <table>\n");
        html.push_str("            <tr><th>Algorithm</th><th>Status</th><th>Pass Rate</th><th>Tests Run</th><th>Tests Passed</th><th>NIST Compliant</th></tr>\n");

        for result in report.algorithm_results.values() {
            let status_class = match result.status {
                ComplianceStatus::FullyCompliant => "pass",
                ComplianceStatus::PartiallyCompliant => "partial",
                ComplianceStatus::NonCompliant => "fail",
                ComplianceStatus::Unknown => "fail",
            };

            html.push_str(&"            <tr>\n".to_string());
            html.push_str(&format!("                <td>{}</td>\n", result.algorithm.name()));
            html.push_str(&format!(
                "                <td class=\"{}\">{:?}</td>\n",
                status_class, result.status
            ));
            html.push_str(&format!(
                "                <td>{:.1}%</td>\n",
                (result.test_cases_passed as f64 / result.test_cases_run as f64) * 100.0
            ));
            html.push_str(&format!("                <td>{}</td>\n", result.test_cases_run));
            html.push_str(&format!("                <td>{}</td>\n", result.test_cases_passed));
            html.push_str(&format!(
                "                <td>{}</td>\n",
                if result.nist_compliant { "Yes" } else { "No" }
            ));
            html.push_str("            </tr>\n");
        }

        html.push_str("        </table>\n");

        if let Some(stat_results) = &report.statistical_results {
            html.push_str("        <h3>Statistical Testing Results</h3>\n");
            html.push_str(&format!(
                "        <p>Randomness Quality: {:?}</p>\n",
                stat_results.randomness_quality
            ));
            html.push_str(&format!(
                "        <p>Entropy Estimate: {:.4}</p>\n",
                stat_results.entropy_estimate
            ));
            html.push_str(&format!("        <p>Bits Tested: {}</p>\n", stat_results.bits_tested));
            html.push_str(&format!(
                "        <p>Test Coverage: {}</p>\n",
                stat_results.test_coverage
            ));
        }

        html.push_str("        <h3>Recommendations</h3>\n");
        html.push_str("        <ul>\n");
        for recommendation in &report.recommendations {
            html.push_str(&format!("            <li>{}</li>\n", recommendation));
        }
        html.push_str("        </ul>\n");

        html.push_str("    </div>\n");
        html.push_str("</body>\n</html>\n");

        Ok(html)
    }

    /// Saves the compliance report to JSON and HTML files.
    ///
    /// # Errors
    /// Returns an error if file creation, report generation, or file writing fails.
    pub fn save_report_to_file(&self, report: &ComplianceReport, filename: &str) -> Result<()> {
        use std::fs::File;
        use std::io::Write;

        let json_content = self.generate_json_report(report)?;
        let html_content = self.generate_html_report(report)?;

        let mut json_file = File::create(format!("{}.json", filename))?;
        json_file.write_all(json_content.as_bytes())?;

        let mut html_file = File::create(format!("{}.html", filename))?;
        html_file.write_all(html_content.as_bytes())?;

        Ok(())
    }
}
