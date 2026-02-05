#![deny(unsafe_code)]
#![allow(missing_docs)]
#![warn(clippy::unwrap_used)]
#![deny(clippy::panic)]
#![allow(clippy::arithmetic_side_effects)]

//! KAT Test Runner
//!
//! Provides a unified test runner for executing and reporting on Known Answer Tests.

use super::{KatTestResult, NistKatError};
use std::time::Instant;

/// Summary of KAT test execution
#[derive(Debug, Clone)]
pub struct KatSummary {
    /// Total number of tests run
    pub total: usize,
    /// Number of tests passed
    pub passed: usize,
    /// Number of tests failed
    pub failed: usize,
    /// Individual test results
    pub results: Vec<KatTestResult>,
    /// Total execution time in milliseconds
    pub total_time_ms: u128,
}

impl KatSummary {
    /// Create a new empty summary
    #[must_use]
    pub fn new() -> Self {
        Self { total: 0, passed: 0, failed: 0, results: Vec::new(), total_time_ms: 0 }
    }

    /// Add a test result
    pub fn add_result(&mut self, result: KatTestResult) {
        self.total += 1;
        if result.passed {
            self.passed += 1;
        } else {
            self.failed += 1;
        }
        self.total_time_ms += result.execution_time_us / 1000;
        self.results.push(result);
    }

    /// Check if all tests passed
    #[must_use]
    pub fn all_passed(&self) -> bool {
        self.failed == 0
    }

    /// Get pass rate as percentage
    #[must_use]
    #[allow(clippy::cast_precision_loss)] // Precision loss acceptable for percentage display
    pub fn pass_rate(&self) -> f64 {
        if self.total == 0 { 0.0 } else { (self.passed as f64 / self.total as f64) * 100.0 }
    }

    /// Print summary to stdout
    pub fn print(&self) {
        println!("\n========================================");
        println!("NIST KAT Test Summary");
        println!("========================================");
        println!("Total Tests:  {}", self.total);
        println!("Passed:       {} ({:.1}%)", self.passed, self.pass_rate());
        println!("Failed:       {}", self.failed);
        println!("Total Time:   {} ms", self.total_time_ms);

        if !self.results.is_empty() {
            println!("\nPer-Algorithm Breakdown:");
            println!("----------------------------------------");

            // Group by algorithm
            let mut by_algorithm: std::collections::HashMap<String, Vec<&KatTestResult>> =
                std::collections::HashMap::new();

            for result in &self.results {
                by_algorithm.entry(result.algorithm.clone()).or_default().push(result);
            }

            for (algorithm, tests) in by_algorithm {
                let passed = tests.iter().filter(|t| t.passed).count();
                let total = tests.len();
                let time_ms: u128 = tests.iter().map(|t| t.execution_time_us / 1000).sum();
                println!("  {:<20} {}/{} passed  ({} ms)", algorithm, passed, total, time_ms);
            }
        }

        if self.failed > 0 {
            println!("\nFailed Tests:");
            println!("----------------------------------------");
            for result in &self.results {
                if !result.passed {
                    println!("  {} - {}", result.algorithm, result.test_case);
                    if let Some(ref err) = result.error_message {
                        println!("    Error: {}", err);
                    }
                }
            }
        }

        println!("========================================\n");
    }
}

impl Default for KatSummary {
    fn default() -> Self {
        Self::new()
    }
}

/// KAT test runner
pub struct KatRunner {
    summary: KatSummary,
}

impl KatRunner {
    /// Create a new runner
    #[must_use]
    pub fn new() -> Self {
        Self { summary: KatSummary::new() }
    }

    /// Run a test and record the result
    pub fn run_test<F>(&mut self, test_case: &str, algorithm: &str, test_fn: F)
    where
        F: FnOnce() -> Result<(), NistKatError>,
    {
        let start = Instant::now();
        let result = test_fn();
        let elapsed = start.elapsed().as_micros();

        let test_result = match result {
            Ok(()) => KatTestResult::passed(test_case.to_string(), algorithm.to_string(), elapsed),
            Err(e) => KatTestResult::failed(
                test_case.to_string(),
                algorithm.to_string(),
                e.to_string(),
                elapsed,
            ),
        };

        self.summary.add_result(test_result);
    }

    /// Get the summary
    #[must_use]
    pub fn summary(&self) -> &KatSummary {
        &self.summary
    }

    /// Consume the runner and return the summary
    #[must_use]
    pub fn finish(self) -> KatSummary {
        self.summary
    }
}

impl Default for KatRunner {
    fn default() -> Self {
        Self::new()
    }
}
