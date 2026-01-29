#![deny(unsafe_code)]
#![allow(missing_docs)]
#![warn(clippy::unwrap_used)]
#![deny(clippy::panic)]
// JUSTIFICATION: NIST SP 800-22 statistical test suite implementation.
// - Statistical analysis requires floating-point arithmetic
// - Probability calculations with integer-to-float conversions
// - Test methods kept on instance for API consistency
// - Result<> used for API consistency across test functions
#![allow(clippy::arithmetic_side_effects)]
#![allow(clippy::cast_precision_loss)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::indexing_slicing)]
#![allow(clippy::unused_self)]
#![allow(clippy::unnecessary_wraps)]
#![allow(clippy::manual_let_else)]
#![allow(clippy::vec_init_then_push)]
#![allow(clippy::doc_lazy_continuation)]

//! NIST SP 800-22 Statistical Test Suite Implementation
//!
//! This module implements statistical tests for random number generators
//! as specified in NIST Special Publication 800-22.
//!
//! # Statistical Calculations
//! This code performs statistical analysis which inherently requires:
//! - Floating point arithmetic for probability calculations
//! - Integer to float conversions for statistical formulas
//! These operations are mathematically correct for statistical testing.

use crate::kat_tests::types::{NistStatisticalTestResult, RngTestResults};
use anyhow::Result;
use libm::{erf, exp, fabs, log, pow, sqrt};
use std::collections::HashMap;

/// NIST SP 800-22 statistical tester
pub struct NistSp800_22Tester {
    significance_level: f64,
    min_sequence_length: usize,
}

impl Default for NistSp800_22Tester {
    fn default() -> Self {
        Self { significance_level: 0.01, min_sequence_length: 1000 }
    }
}

impl NistSp800_22Tester {
    /// Create a new tester with specified parameters
    #[must_use]
    pub fn new(significance_level: f64, min_sequence_length: usize) -> Self {
        Self { significance_level, min_sequence_length }
    }

    /// Test a bit sequence using NIST SP 800-22 tests.
    ///
    /// # Errors
    /// This function is infallible but returns Result for API consistency.
    #[allow(clippy::arithmetic_side_effects)] // Statistical calculations require arithmetic
    pub fn test_bit_sequence(&self, data: &[u8]) -> Result<RngTestResults> {
        let min_bytes = self.min_sequence_length.saturating_div(8);
        if data.len() < min_bytes {
            return Ok(RngTestResults {
                algorithm: "unknown".to_string(),
                bits_tested: data.len().saturating_mul(8),
                test_results: vec![],
                passed: false,
                entropy_estimate: 0.0,
            });
        }

        let bits = self.bytes_to_bits(data);
        let mut test_results = Vec::new();

        test_results.push(self.frequency_test(&bits)?);
        test_results.push(self.frequency_within_block_test(&bits)?);
        test_results.push(self.runs_test(&bits)?);
        test_results.push(self.longest_run_of_ones_test(&bits)?);
        test_results.push(self.serial_test(&bits)?);
        test_results.push(self.approximate_entropy_test(&bits)?);

        let entropy_estimate = self.estimate_entropy(&bits);
        let passed = test_results.iter().all(|r| r.passed);

        Ok(RngTestResults {
            algorithm: "NIST SP 800-22".to_string(),
            bits_tested: bits.len(),
            test_results,
            passed,
            entropy_estimate,
        })
    }

    /// Convert bytes to bits
    #[allow(clippy::arithmetic_side_effects)] // Bit manipulation is safe
    #[must_use]
    pub fn bytes_to_bits(&self, bytes: &[u8]) -> Vec<bool> {
        bytes
            .iter()
            .flat_map(|&b| (0..8).map(move |i| (b >> (7_u8.saturating_sub(i))) & 1 == 1))
            .collect()
    }

    /// Frequency (Monobit) Test
    #[allow(clippy::arithmetic_side_effects, clippy::cast_precision_loss)] // Statistical math
    fn frequency_test(&self, bits: &[bool]) -> Result<NistStatisticalTestResult> {
        let n = bits.len() as f64;
        let ones = bits.iter().filter(|&&b| b).count() as f64;
        let proportion = ones / n;

        let s_obs = fabs(ones - n / 2.0) / sqrt(n / 4.0);
        let p_value = erf(s_obs / sqrt(2.0));

        Ok(NistStatisticalTestResult {
            test_name: "Frequency (Monobit) Test".to_string(),
            p_value,
            passed: p_value > self.significance_level,
            parameters: serde_json::json!({
                "significance_level": self.significance_level,
                "proportion_of_ones": proportion,
                "s_obs": s_obs
            }),
        })
    }

    /// Frequency Within Block Test
    #[allow(clippy::arithmetic_side_effects, clippy::cast_precision_loss)] // Statistical math
    fn frequency_within_block_test(&self, bits: &[bool]) -> Result<NistStatisticalTestResult> {
        let n = bits.len();
        let block_size = if n >= 1000 { 10000 } else { n.saturating_div(10) };
        let num_blocks = n.saturating_div(block_size);

        if num_blocks < 1 || block_size == 0 {
            return Ok(NistStatisticalTestResult {
                test_name: "Frequency Within Block Test".to_string(),
                p_value: 0.0,
                passed: false,
                parameters: serde_json::json!({"error": "insufficient data"}),
            });
        }

        let mut chi_squared = 0.0;
        for i in 0..num_blocks {
            let start = i.saturating_mul(block_size);
            let end = start.saturating_add(block_size).min(bits.len());

            let block = match bits.get(start..end) {
                Some(b) => b,
                None => continue,
            };

            if block.is_empty() {
                continue;
            }

            let ones = block.iter().filter(|&&b| b).count() as f64;
            let block_len = block.len() as f64;
            let proportion = ones / block_len;
            chi_squared += 4.0 * block_len * pow(proportion - 0.5, 2.0);
        }

        let degrees_of_freedom = num_blocks as f64;
        let p_value = 1.0 - self.igamc(degrees_of_freedom / 2.0, chi_squared / 2.0);

        Ok(NistStatisticalTestResult {
            test_name: "Frequency Within Block Test".to_string(),
            p_value,
            passed: p_value > self.significance_level,
            parameters: serde_json::json!({
                "block_size": block_size,
                "num_blocks": num_blocks,
                "chi_squared": chi_squared,
                "degrees_of_freedom": degrees_of_freedom
            }),
        })
    }

    /// Runs Test
    #[allow(clippy::arithmetic_side_effects, clippy::cast_precision_loss)] // Statistical math
    fn runs_test(&self, bits: &[bool]) -> Result<NistStatisticalTestResult> {
        let n = bits.len() as f64;
        let ones = bits.iter().filter(|&&b| b).count() as f64;
        let proportion = ones / n;

        if fabs(proportion - 0.5) < 1e-10 {
            return Ok(NistStatisticalTestResult {
                test_name: "Runs Test".to_string(),
                p_value: 0.0,
                passed: false,
                parameters: serde_json::json!({"error": "proportion too close to 0.5"}),
            });
        }

        let runs = self.count_runs(bits) as f64;

        let expected_runs = 2.0 * n * proportion * (1.0 - proportion);
        let variance = 2.0 * n * proportion * (1.0 - proportion);

        let test_statistic = fabs(runs - expected_runs) / sqrt(variance);
        let p_value = erf(test_statistic / sqrt(2.0));

        Ok(NistStatisticalTestResult {
            test_name: "Runs Test".to_string(),
            p_value,
            passed: p_value > self.significance_level,
            parameters: serde_json::json!({
                "runs": runs,
                "expected_runs": expected_runs,
                "proportion": proportion,
                "test_statistic": test_statistic
            }),
        })
    }

    /// Longest Run of Ones Test
    #[allow(clippy::arithmetic_side_effects, clippy::cast_precision_loss)] // Statistical math
    fn longest_run_of_ones_test(&self, bits: &[bool]) -> Result<NistStatisticalTestResult> {
        let n = bits.len();
        let (block_size, k, expected_probabilities): (usize, usize, Vec<f64>) = match n {
            128..=6272 => (8, 3, vec![0.2148, 0.3672, 0.2305, 0.1875]),
            6273..=75000 => (128, 5, vec![0.1174, 0.2430, 0.2493, 0.1752, 0.1027, 0.1124]),
            _ => (10000, 6, vec![0.0882, 0.2092, 0.2483, 0.1933, 0.1208, 0.0675, 0.0727]),
        };

        if n < block_size {
            return Ok(NistStatisticalTestResult {
                test_name: "Longest Run of Ones Test".to_string(),
                p_value: 0.0,
                passed: false,
                parameters: serde_json::json!({"error": "insufficient data for test"}),
            });
        }

        let num_blocks = n.saturating_div(block_size);
        let mut category_counts = vec![0.0; k.saturating_add(1)];

        for i in 0..num_blocks {
            let start = i.saturating_mul(block_size);
            let end = start.saturating_add(block_size).min(bits.len());

            let block = match bits.get(start..end) {
                Some(b) => b,
                None => continue,
            };

            let longest_run = self.longest_run_of_ones_in_block(block);
            let category = if longest_run <= k { longest_run } else { k };
            if let Some(count) = category_counts.get_mut(category) {
                *count += 1.0;
            }
        }

        let chi_squared =
            self.compute_chi_squared(&category_counts, &expected_probabilities, num_blocks as f64);
        let p_value = 1.0 - self.igamc(k as f64 / 2.0, chi_squared / 2.0);

        Ok(NistStatisticalTestResult {
            test_name: "Longest Run of Ones in a Block Test".to_string(),
            p_value,
            passed: p_value > self.significance_level,
            parameters: serde_json::json!({
                "block_size": block_size,
                "num_blocks": num_blocks,
                "chi_squared": chi_squared,
                "k": k
            }),
        })
    }

    /// Serial Test
    #[allow(clippy::arithmetic_side_effects, clippy::cast_precision_loss)] // Statistical math
    fn serial_test(&self, bits: &[bool]) -> Result<NistStatisticalTestResult> {
        let log2_len = bits.len().checked_ilog2().unwrap_or(0) as usize;
        let m = std::cmp::min(16, log2_len.saturating_sub(3));

        if m < 2 {
            return Ok(NistStatisticalTestResult {
                test_name: "Serial Test".to_string(),
                p_value: 0.0,
                passed: false,
                parameters: serde_json::json!({"error": "insufficient data for serial test"}),
            });
        }

        let psi_m = self.compute_psi_m(bits, m);
        let psi_m_minus_1 = self.compute_psi_m(bits, m.saturating_sub(1));
        let psi_m_minus_2 = self.compute_psi_m(bits, m.saturating_sub(2));

        let del1 = psi_m - psi_m_minus_1;
        let del2 = psi_m - 2.0 * psi_m_minus_1 + psi_m_minus_2;

        let degrees1 = pow(2.0, (m as f64) - 1.0);
        let degrees2 = pow(2.0, (m as f64) - 2.0);

        let p_value1 = self.igamc(degrees1 / 2.0, del1 / 2.0);
        let p_value2 = self.igamc(degrees2 / 2.0, del2 / 2.0);

        let passed = p_value1 > self.significance_level && p_value2 > self.significance_level;

        Ok(NistStatisticalTestResult {
            test_name: "Serial Test".to_string(),
            p_value: p_value1.min(p_value2),
            passed,
            parameters: serde_json::json!({
                "m": m,
                "p_value1": p_value1,
                "p_value2": p_value2,
                "del1": del1,
                "del2": del2,
                "degrees1": degrees1,
                "degrees2": degrees2
            }),
        })
    }

    /// Approximate Entropy Test
    #[allow(clippy::arithmetic_side_effects, clippy::cast_precision_loss)] // Statistical math
    fn approximate_entropy_test(&self, bits: &[bool]) -> Result<NistStatisticalTestResult> {
        let log2_len = bits.len().checked_ilog2().unwrap_or(0) as usize;
        let m = std::cmp::min(16, log2_len.saturating_sub(3));

        if m < 2 {
            return Ok(NistStatisticalTestResult {
                test_name: "Approximate Entropy Test".to_string(),
                p_value: 0.0,
                passed: false,
                parameters: serde_json::json!({"error": "insufficient data for entropy test"}),
            });
        }

        let phi_m = self.compute_approximate_entropy(bits, m);
        let phi_m_plus_1 = self.compute_approximate_entropy(bits, m.saturating_add(1));
        let chi_squared = 2.0 * (bits.len() as f64) * (log(2.0) * (phi_m - phi_m_plus_1));

        let degrees_of_freedom = pow(2.0, m as f64);
        let p_value = self.igamc(degrees_of_freedom / 2.0, chi_squared / 2.0);

        Ok(NistStatisticalTestResult {
            test_name: "Approximate Entropy Test".to_string(),
            p_value,
            passed: p_value > self.significance_level,
            parameters: serde_json::json!({
                "m": m,
                "chi_squared": chi_squared,
                "phi_m": phi_m,
                "phi_m_plus_1": phi_m_plus_1,
                "degrees_of_freedom": degrees_of_freedom
            }),
        })
    }

    /// Count runs in bit sequence
    #[allow(clippy::unused_self)] // Method of struct for consistency
    fn count_runs(&self, bits: &[bool]) -> usize {
        if bits.is_empty() {
            return 0;
        }

        let mut runs = 1usize;
        for i in 1..bits.len() {
            if let (Some(&current_bit), Some(&prev_bit)) =
                (bits.get(i), bits.get(i.saturating_sub(1)))
                && current_bit != prev_bit
            {
                runs = runs.saturating_add(1);
            }
        }
        runs
    }

    /// Find longest run of ones in a block
    #[allow(clippy::unused_self)] // Method of struct for consistency
    fn longest_run_of_ones_in_block(&self, block: &[bool]) -> usize {
        let mut max_run = 0usize;
        let mut current_run = 0usize;

        for &bit in block {
            if bit {
                current_run = current_run.saturating_add(1);
                max_run = max_run.max(current_run);
            } else {
                current_run = 0;
            }
        }
        max_run
    }

    /// Compute chi-squared statistic
    #[allow(clippy::arithmetic_side_effects, clippy::unused_self)] // Statistical calculation
    fn compute_chi_squared(&self, observed: &[f64], expected: &[f64], total: f64) -> f64 {
        observed
            .iter()
            .zip(expected.iter())
            .map(|(&o, &e)| {
                let exp = e * total;
                if exp == 0.0 { 0.0 } else { pow(o - exp, 2.0) / exp }
            })
            .sum()
    }

    /// Compute psi_m statistic for serial test
    #[allow(clippy::arithmetic_side_effects, clippy::cast_precision_loss, clippy::unused_self)] // Statistical math
    fn compute_psi_m(&self, bits: &[bool], m: usize) -> f64 {
        let mut counts = HashMap::new();
        let n = bits.len();

        if n < m || m == 0 {
            return 0.0;
        }

        let iterations = n.saturating_sub(m).saturating_add(1);
        for i in 0..iterations {
            let mut pattern = 0u64;
            for j in 0..m {
                if let Some(&bit) = bits.get(i.saturating_add(j)) {
                    pattern = (pattern << 1) | if bit { 1 } else { 0 };
                }
            }
            *counts.entry(pattern).or_insert(0.0) += 1.0;
        }

        let total_sequences = iterations as f64;
        if total_sequences == 0.0 {
            return 0.0;
        }
        counts.values().map(|&count| pow(count, 2.0)).sum::<f64>() / total_sequences
    }

    /// Compute approximate entropy
    #[allow(clippy::arithmetic_side_effects, clippy::cast_precision_loss, clippy::unused_self)] // Statistical math
    fn compute_approximate_entropy(&self, bits: &[bool], m: usize) -> f64 {
        let mut counts = HashMap::new();
        let n = bits.len();

        if n < m || m == 0 {
            return 0.0;
        }

        let iterations = n.saturating_sub(m).saturating_add(1);
        for i in 0..iterations {
            let mut pattern = 0u64;
            for j in 0..m {
                if let Some(&bit) = bits.get(i.saturating_add(j)) {
                    pattern = (pattern << 1) | if bit { 1 } else { 0 };
                }
            }
            *counts.entry(pattern).or_insert(0.0) += 1.0;
        }

        let total_sequences = iterations as f64;
        if total_sequences == 0.0 {
            return 0.0;
        }

        let mut entropy = 0.0;

        for &count in counts.values() {
            let p = count / total_sequences;
            if p > 0.0 {
                entropy += p * log(p) / log(2.0);
            }
        }

        -entropy
    }

    /// Estimate entropy of bit sequence
    #[allow(clippy::arithmetic_side_effects, clippy::cast_precision_loss)] // Statistical math
    #[must_use]
    pub fn estimate_entropy(&self, bits: &[bool]) -> f64 {
        if bits.is_empty() {
            return 0.0;
        }

        let ones = bits.iter().filter(|&&b| b).count() as f64;
        let proportion = ones / (bits.len() as f64);

        if proportion <= 0.0 || proportion >= 1.0 {
            return 0.0;
        }

        -proportion * log(proportion) / log(2.0)
            - (1.0 - proportion) * log(1.0 - proportion) / log(2.0)
    }

    /// Incomplete gamma function (upper)
    #[allow(clippy::arithmetic_side_effects, clippy::unused_self)] // Mathematical function
    fn igamc(&self, a: f64, x: f64) -> f64 {
        if x <= 0.0 {
            return 1.0;
        }
        if a <= 0.0 {
            return 0.0;
        }
        if x < a + 1.0 { 1.0 - self.igam(a, x) } else { self.igamc_series(a, x) }
    }

    /// Incomplete gamma function (lower)
    #[allow(clippy::arithmetic_side_effects, clippy::unused_self)] // Mathematical function
    fn igam(&self, a: f64, x: f64) -> f64 {
        if x <= 0.0 {
            return 0.0;
        }
        if a <= 0.0 {
            return 1.0;
        }
        if x < a + 1.0 { self.igam_series(a, x) } else { 1.0 - self.igamc_series(a, x) }
    }

    /// Incomplete gamma function series expansion
    #[allow(clippy::arithmetic_side_effects, clippy::cast_precision_loss, clippy::unused_self)] // Mathematical function
    fn igam_series(&self, a: f64, x: f64) -> f64 {
        let ax = a * log(x) - x - self.log_gamma(a);
        if ax < -709.782_712_893_384 {
            return 0.0;
        }

        let term = exp(ax);
        let mut sum = term;
        let mut c = 1.0;

        for n in 1..1000 {
            let denom = a + f64::from(n) - 1.0;
            if denom == 0.0 {
                break;
            }
            c *= x / denom;
            let next_term = c * term;
            sum += next_term;
            if fabs(next_term / sum) < 1e-15 {
                break;
            }
        }

        if a == 0.0 { 0.0 } else { sum / a }
    }

    /// Incomplete gamma function continued fraction
    #[allow(clippy::arithmetic_side_effects, clippy::cast_precision_loss, clippy::unused_self)] // Mathematical function
    fn igamc_series(&self, a: f64, x: f64) -> f64 {
        let ax = a * log(x) - x - self.log_gamma(a);
        if ax < -709.782_712_893_384 {
            return 0.0;
        }

        if x == 0.0 {
            return 0.0;
        }

        let term = exp(ax) / x;
        let mut sum = term;
        let mut c = 1.0;

        for n in 1..1000 {
            c *= (a - f64::from(n)) / x;
            let next_term = c * term;
            sum += next_term;
            if fabs(next_term / sum) < 1e-15 {
                break;
            }
        }

        sum
    }

    /// Log gamma function (Lanczos approximation)
    #[allow(clippy::arithmetic_side_effects, clippy::unused_self)] // Mathematical function
    fn log_gamma(&self, x: f64) -> f64 {
        let cof = [
            76.18009172947146,
            -86.50532032941677,
            24.01409824083091,
            -1.231739572450155,
            0.1208650973866179e-2,
            -0.5395239384953e-5,
        ];

        let mut y = x;
        let mut tmp = x + 5.5;
        tmp -= (x + 0.5) * log(tmp);
        let mut ser = 1.000000000190015;

        for j in 0..6 {
            y += 1.0;
            if let Some(&cof_val) = cof.get(j)
                && y != 0.0
            {
                ser += cof_val / y;
            }
        }

        if x == 0.0 {
            return 0.0;
        }

        -tmp + log(2.5066282746310005 * ser / x)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_frequency_test() {
        let tester = NistSp800_22Tester::default();
        let data = vec![0x00; 1000];
        let result = tester.test_bit_sequence(&data).unwrap();

        assert!(!result.passed);
        assert_eq!(result.bits_tested, 8000);
    }

    #[test]
    fn test_runs_test() {
        let tester = NistSp800_22Tester::default();
        let data = (0u8..100).map(|i| i % 2).collect::<Vec<_>>();
        let result = tester.test_bit_sequence(&data).unwrap();

        assert_eq!(result.bits_tested, 800);
    }

    #[test]
    fn test_random_data() {
        let tester = NistSp800_22Tester::default();
        use rand::RngCore;
        let mut data = vec![0u8; 1000];
        rand::thread_rng().fill_bytes(&mut data);

        let result = tester.test_bit_sequence(&data).unwrap();
        assert_eq!(result.bits_tested, 8000);
    }
}
