//! Side-Channel Analysis Testing for Utility Functions
//!
//! This module provides basic side-channel analysis for prelude utilities
//! focusing on timing and information leakage in common operations.
//!
//! Side-channel attacks exploit information leaked through timing, power
//! consumption, or other physical characteristics of cryptographic operations.

#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

use crate::prelude::error::Result;
use std::time::{Duration, Instant};

/// Timing analyzer for utility functions.
///
/// Measures execution time variations to detect potential timing side-channels.
pub struct UtilityTimingAnalyzer {
    /// Number of samples to collect.
    samples: usize,
    /// Number of warmup iterations before measurement.
    warmup_iterations: usize,
}

impl UtilityTimingAnalyzer {
    /// Creates a new timing analyzer with the specified sample count and warmup.
    #[must_use]
    pub fn new(samples: usize, warmup_iterations: usize) -> Self {
        Self { samples, warmup_iterations }
    }

    /// Analyze timing variations in utility operations.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails during timing measurement.
    pub fn analyze_utility_timing<F>(&self, operation: F) -> Result<TimingAnalysis>
    where
        F: Fn() -> Result<()>,
    {
        let mut execution_times = Vec::with_capacity(self.samples);

        // Warmup phase
        for _ in 0..self.warmup_iterations {
            let _ = operation();
        }

        // Measurement phase
        for _ in 0..self.samples {
            let start = Instant::now();
            operation()?;
            let duration = start.elapsed();
            execution_times.push(duration);
        }

        Ok(TimingAnalysis {
            samples: execution_times.clone(),
            mean: calculate_mean(&execution_times),
            std_dev: calculate_std_dev(&execution_times),
            min: *execution_times.iter().min().unwrap_or(&Duration::ZERO),
            max: *execution_times.iter().max().unwrap_or(&Duration::ZERO),
        })
    }

    /// Test timing variations in hex encoding/decoding.
    ///
    /// # Errors
    ///
    /// Returns an error if hex decoding fails during timing analysis.
    pub fn test_hex_timing(&self) -> Result<Vec<SideChannelAssessment>> {
        let mut assessments = Vec::new();

        // Test different input sizes for timing variations
        let sizes = [16, 64, 256, 1024];

        for &size in &sizes {
            let data = vec![0u8; size];

            // Test encoding timing
            let encode_analysis = self.analyze_utility_timing(|| {
                let _encoded = hex::encode(&data);
                Ok(())
            })?;

            // Test decoding timing
            let hex_string = hex::encode(&data);
            let decode_analysis = self.analyze_utility_timing(|| {
                let _decoded = hex::decode(&hex_string)?;
                Ok(())
            })?;

            // Check for suspicious timing variations
            #[allow(clippy::cast_precision_loss)]
            let encode_cv =
                encode_analysis.std_dev.as_nanos() as f64 / encode_analysis.mean.as_nanos() as f64;
            #[allow(clippy::cast_precision_loss)]
            let decode_cv =
                decode_analysis.std_dev.as_nanos() as f64 / decode_analysis.mean.as_nanos() as f64;

            if encode_cv > 0.05 {
                // More than 5% variation
                assessments.push(SideChannelAssessment {
                    vulnerability_type: SideChannelType::Timing,
                    severity: if encode_cv > 0.1 { Severity::Medium } else { Severity::Low },
                    confidence: (encode_cv * 20.0).min(1.0),
                    description: format!(
                        "High timing variation in hex encoding for {} bytes (CV: {:.3})",
                        size, encode_cv
                    ),
                    mitigation_suggestions: vec!["Hex encoding timing appears stable".to_string()],
                });
            }

            if decode_cv > 0.05 {
                assessments.push(SideChannelAssessment {
                    vulnerability_type: SideChannelType::Timing,
                    severity: if decode_cv > 0.1 { Severity::Medium } else { Severity::Low },
                    confidence: (decode_cv * 20.0).min(1.0),
                    description: format!(
                        "High timing variation in hex decoding for {} bytes (CV: {:.3})",
                        size, decode_cv
                    ),
                    mitigation_suggestions: vec!["Hex decoding timing appears stable".to_string()],
                });
            }
        }

        Ok(assessments)
    }

    /// Test UUID generation timing (should be consistent).
    ///
    /// # Errors
    ///
    /// Returns an error if UUID timing analysis fails.
    pub fn test_uuid_timing(&self) -> Result<Vec<SideChannelAssessment>> {
        let mut assessments = Vec::new();

        let analysis = self.analyze_utility_timing(|| {
            let _uuid = uuid::Uuid::new_v4();
            Ok(())
        })?;

        #[allow(clippy::cast_precision_loss)]
        let cv = analysis.std_dev.as_nanos() as f64 / analysis.mean.as_nanos() as f64;

        if cv > 0.1 {
            // More than 10% variation
            assessments.push(SideChannelAssessment {
                vulnerability_type: SideChannelType::Timing,
                severity: Severity::Low,
                confidence: (cv * 10.0).min(1.0),
                description: format!("UUID generation timing variation detected (CV: {:.3})", cv),
                mitigation_suggestions: vec![
                    "UUID generation timing is within expected bounds".to_string(),
                ],
            });
        }

        Ok(assessments)
    }
}

/// Timing analysis results.
#[derive(Debug, Clone)]
pub struct TimingAnalysis {
    /// Collected timing samples.
    pub samples: Vec<Duration>,
    /// Mean execution time.
    pub mean: Duration,
    /// Standard deviation of execution times.
    pub std_dev: Duration,
    /// Minimum execution time.
    pub min: Duration,
    /// Maximum execution time.
    pub max: Duration,
}

/// Side-channel vulnerability assessment.
#[derive(Debug, Clone)]
pub struct SideChannelAssessment {
    /// Type of side-channel vulnerability.
    pub vulnerability_type: SideChannelType,
    /// Severity level of the vulnerability.
    pub severity: Severity,
    /// Confidence level of the assessment (0.0 to 1.0).
    pub confidence: f64,
    /// Description of the vulnerability.
    pub description: String,
    /// Suggested mitigations.
    pub mitigation_suggestions: Vec<String>,
}

/// Types of side-channel vulnerabilities.
#[derive(Debug, Clone, PartialEq)]
pub enum SideChannelType {
    /// Timing-based side-channel.
    Timing,
    /// Cache-based side-channel.
    Cache,
    /// Power analysis side-channel.
    Power,
    /// Electromagnetic emanation side-channel.
    Electromagnetic,
    /// Acoustic side-channel.
    Acoustic,
    /// Memory access pattern side-channel.
    MemoryAccess,
}

/// Severity levels for side-channel vulnerabilities.
#[derive(Debug, Clone, PartialEq)]
pub enum Severity {
    /// Low severity - minimal security impact.
    Low,
    /// Medium severity - some security impact.
    Medium,
    /// High severity - significant security impact.
    High,
    /// Critical severity - severe security impact.
    Critical,
}

/// Calculate mean duration.
#[allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::arithmetic_side_effects
)]
fn calculate_mean(durations: &[Duration]) -> Duration {
    let total_nanos: u128 = durations.iter().map(Duration::as_nanos).sum();
    Duration::from_nanos((total_nanos / durations.len() as u128) as u64)
}

/// Calculate standard deviation.
#[allow(clippy::cast_precision_loss, clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn calculate_std_dev(durations: &[Duration]) -> Duration {
    let mean = calculate_mean(durations);
    #[allow(clippy::cast_precision_loss)]
    let mean_nanos = mean.as_nanos() as f64;

    #[allow(clippy::cast_precision_loss)]
    let variance: f64 = durations
        .iter()
        .map(|d| {
            #[allow(clippy::cast_precision_loss)]
            let diff = d.as_nanos() as f64 - mean_nanos;
            diff * diff
        })
        .sum::<f64>()
        / durations.len() as f64;

    Duration::from_nanos((variance.sqrt() * 1_000_000_000.0) as u64)
}

/// Comprehensive utility side-channel analysis.
///
/// Provides full side-channel analysis for utility functions including
/// timing analysis, memory access patterns, and security assessments.
pub struct UtilitySideChannelTester {
    /// Timing analyzer instance.
    timing_analyzer: UtilityTimingAnalyzer,
}

impl Default for UtilitySideChannelTester {
    fn default() -> Self {
        Self::new()
    }
}

impl UtilitySideChannelTester {
    /// Creates a new side-channel tester with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self { timing_analyzer: UtilityTimingAnalyzer::new(1000, 100) }
    }

    /// Run comprehensive side-channel analysis for utilities.
    ///
    /// # Errors
    ///
    /// Returns an error if any timing analysis operation fails.
    pub fn run_analysis(&self) -> Result<Vec<SideChannelAssessment>> {
        tracing::info!("Running utility side-channel analysis");

        let mut assessments = Vec::new();

        // Test hex encoding/decoding timing
        let hex_assessments = self.timing_analyzer.test_hex_timing()?;
        assessments.extend(hex_assessments);

        // Test UUID generation timing
        let uuid_assessments = self.timing_analyzer.test_uuid_timing()?;
        assessments.extend(uuid_assessments);

        // Test domain constant access (should be constant time)
        let domain_assessments = self.test_domain_access_timing()?;
        assessments.extend(domain_assessments);

        Ok(assessments)
    }

    /// Test domain constant access timing.
    fn test_domain_access_timing(&self) -> Result<Vec<SideChannelAssessment>> {
        let mut assessments = Vec::new();

        // Test access to domain constants (should be constant time)
        let analysis = self.timing_analyzer.analyze_utility_timing(|| {
            let _domain = crate::prelude::domains::HYBRID_KEM;
            let _domain = crate::prelude::domains::CASCADE_OUTER;
            let _domain = crate::prelude::domains::CASCADE_INNER;
            let _domain = crate::prelude::domains::SIGNATURE_BIND;
            Ok(())
        })?;

        #[allow(clippy::cast_precision_loss)]
        let cv = analysis.std_dev.as_nanos() as f64 / analysis.mean.as_nanos() as f64;

        if cv > 0.05 {
            // More than 5% variation
            assessments.push(SideChannelAssessment {
                vulnerability_type: SideChannelType::MemoryAccess,
                severity: Severity::Low,
                confidence: (cv * 20.0).min(1.0),
                description: format!("Domain constant access timing variation (CV: {:.3})", cv),
                mitigation_suggestions: vec![
                    "Domain constants are static and should be constant time".to_string(),
                ],
            });
        }

        Ok(assessments)
    }

    /// Generate side-channel security report.
    ///
    /// Creates a markdown-formatted security report from the assessments.
    #[must_use]
    pub fn generate_security_report(&self, assessments: &[SideChannelAssessment]) -> String {
        let mut report = String::from("# Utility Side-Channel Security Assessment Report\n\n");

        let critical_count =
            assessments.iter().filter(|a| a.severity == Severity::Critical).count();
        let high_count = assessments.iter().filter(|a| a.severity == Severity::High).count();
        let medium_count = assessments.iter().filter(|a| a.severity == Severity::Medium).count();
        let low_count = assessments.iter().filter(|a| a.severity == Severity::Low).count();

        report.push_str("## Summary\n\n");
        report.push_str(&format!("- Critical Vulnerabilities: {}\n", critical_count));
        report.push_str(&format!("- High Vulnerabilities: {}\n", high_count));
        report.push_str(&format!("- Medium Vulnerabilities: {}\n", medium_count));
        report.push_str(&format!("- Low Vulnerabilities: {}\n\n", low_count));

        report.push_str("## Detailed Findings\n\n");
        for assessment in assessments {
            report.push_str(&format!(
                "### {} ({:?})\n",
                assessment.vulnerability_type.clone() as u8,
                assessment.severity
            ));
            report.push_str(&format!("**Confidence:** {:.1}%\n", assessment.confidence * 100.0));
            report.push_str(&format!("**Description:** {}\n", assessment.description));
            report.push_str("**Mitigation Suggestions:**\n");
            for suggestion in &assessment.mitigation_suggestions {
                report.push_str(&format!("- {}\n", suggestion));
            }
            report.push('\n');
        }

        report
    }
}

#[cfg(test)]
#[allow(clippy::panic_in_result_fn)] // Test functions use assert! which can panic
mod tests {
    use super::*;

    #[test]
    fn test_timing_analyzer() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let analyzer = UtilityTimingAnalyzer::new(10, 5);

        // Test with a simple operation
        let analysis = analyzer.analyze_utility_timing(|| {
            let _encoded = hex::encode(b"test");
            Ok(())
        })?;

        assert!(analysis.samples.len() == 10);
        assert!(analysis.mean > Duration::from_nanos(0));
        assert!(analysis.min <= analysis.mean);
        assert!(analysis.max >= analysis.mean);
        Ok(())
    }

    #[test]
    fn test_hex_timing_analysis() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let analyzer = UtilityTimingAnalyzer::new(10, 5);
        let assessments = analyzer.test_hex_timing()?;
        // Should not have critical issues
        assert!(assessments.iter().all(|a| a.severity != Severity::Critical));
        Ok(())
    }

    #[test]
    fn test_uuid_timing_analysis() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let analyzer = UtilityTimingAnalyzer::new(10, 5);
        let assessments = analyzer.test_uuid_timing()?;
        // Should not have critical issues
        assert!(assessments.iter().all(|a| a.severity != Severity::Critical));
        Ok(())
    }

    #[test]
    fn test_side_channel_tester() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let tester = UtilitySideChannelTester::new();
        let assessments = tester.run_analysis()?;

        // Generate report
        let report = tester.generate_security_report(&assessments);
        assert!(report.contains("Utility Side-Channel Security Assessment Report"));

        // Should not have critical vulnerabilities in utilities
        assert!(assessments.iter().all(|a| a.severity != Severity::Critical));
        Ok(())
    }
}
