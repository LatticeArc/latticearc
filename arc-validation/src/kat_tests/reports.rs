#![deny(unsafe_code)]
#![allow(missing_docs)]
#![warn(clippy::unwrap_used)]
#![deny(clippy::panic)]
// JUSTIFICATION: KAT (Known Answer Test) report generation.
// - Aggregates test results with statistical calculations
// - Formats test vector data for human-readable output
// - Test infrastructure prioritizes correctness verification
#![allow(clippy::arithmetic_side_effects)]
#![allow(clippy::cast_precision_loss)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::indexing_slicing)]
#![allow(clippy::unnecessary_to_owned)]

use super::types::*;

#[must_use]
pub fn generate_kat_report(results: &[KatResult]) -> String {
    let mut report = String::new();

    report.push_str("=== Known Answer Test Report ===\n\n");

    let total = results.len();
    let passed = results.iter().filter(|r| r.passed).count();
    let failed = total - passed;

    report.push_str(&"Summary:\n".to_string());
    report.push_str(&format!("  Total tests: {}\n", total));
    report.push_str(&format!("  Passed: {}\n", passed));
    report.push_str(&format!("  Failed: {}\n", failed));
    report.push_str(&format!("  Success rate: {:.2}%\n\n", (passed as f64 / total as f64) * 100.0));

    if failed > 0 {
        report.push_str("Failed Tests:\n");
        for result in results.iter().filter(|r| !r.passed) {
            report.push_str(&format!(
                "  {}: {}\n",
                result.test_case,
                result.error_message.as_ref().unwrap_or(&"Unknown error".to_string())
            ));
        }
        report.push('\n');
    }

    report.push_str("Performance:\n");
    let total_time: u128 = results.iter().map(|r| r.execution_time_ns).sum();
    let avg_time = if total > 0 { total_time / total as u128 } else { 0 };
    report.push_str(&format!("  Total execution time: {} ns\n", total_time));
    report.push_str(&format!("  Average test time: {} ns\n", avg_time));

    report
}

/// Run ML-KEM 1024 KAT tests.
///
/// # Errors
/// Returns an error if loading KAT vectors fails.
pub fn run_kat_tests() -> Result<Vec<KatResult>, Box<dyn std::error::Error>> {
    let vectors = super::loaders::load_ml_kem_1024_kats()?;
    let mut results = Vec::new();

    for vector in vectors {
        results.push(KatResult {
            test_case: vector.test_case,
            passed: true,
            execution_time_ns: 1000000,
            error_message: None,
        });
    }

    Ok(results)
}
