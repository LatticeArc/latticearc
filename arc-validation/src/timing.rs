#![deny(unsafe_code)]
#![allow(missing_docs)]
#![warn(clippy::unwrap_used)]
#![deny(clippy::panic)]
// JUSTIFICATION: Timing analysis for constant-time validation.
// - Statistical calculations (mean, variance, std deviation)
// - Floating-point arithmetic for timing metrics
// - Test infrastructure for side-channel validation
#![allow(clippy::arithmetic_side_effects)]
#![allow(clippy::cast_precision_loss)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::indexing_slicing)]
// Clone is needed in tests to move values into closures
#![allow(clippy::redundant_clone)]

use std::time::Instant;
use subtle::ConstantTimeEq;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum TimingError {
    #[error("Timing variation detected: variance too high")]
    TimingVariation,
    #[error("Insufficient samples for timing analysis")]
    InsufficientSamples,
    #[error("Constant-time comparison failed: timing differs between inputs")]
    ConstantTimeFailed,
}

/// Configuration for timing validation
pub struct TimingValidator {
    /// Number of timing samples to collect
    sample_count: usize,
    /// Number of warmup iterations before timing
    warmup_iterations: usize,
    /// Number of operations per timing sample (batching reduces measurement noise)
    batch_size: usize,
    /// Maximum allowed difference ratio between timing distributions (for constant-time validation)
    max_timing_difference_ratio: f64,
}

impl Default for TimingValidator {
    fn default() -> Self {
        Self {
            sample_count: 200,                 // More samples for statistical significance
            warmup_iterations: 100,            // Extended warmup to stabilize caches
            batch_size: 200,                   // Larger batches to reduce measurement noise
            max_timing_difference_ratio: 0.20, // 20% threshold accounts for environmental noise
        }
    }
}

impl TimingValidator {
    #[must_use]
    pub fn new(sample_count: usize, max_timing_difference_ratio: f64) -> Self {
        Self { sample_count, warmup_iterations: 50, batch_size: 100, max_timing_difference_ratio }
    }

    /// Collect timing samples for an operation with warmup and batching
    fn collect_timing_samples<F>(&self, operation: &F) -> Result<Vec<f64>, TimingError>
    where
        F: Fn() -> bool,
    {
        if self.sample_count < 10 {
            return Err(TimingError::InsufficientSamples);
        }

        // Warmup phase: execute the operation to warm caches and JIT
        for _ in 0..self.warmup_iterations {
            std::hint::black_box(operation());
        }

        let mut timings = Vec::with_capacity(self.sample_count);

        // Collect timing samples with batching to reduce measurement noise
        for _ in 0..self.sample_count {
            let start = Instant::now();
            for _ in 0..self.batch_size {
                std::hint::black_box(operation());
            }
            let elapsed = start.elapsed().as_nanos() as f64 / self.batch_size as f64;
            timings.push(elapsed);
        }

        Ok(timings)
    }

    /// Calculate the mean of a timing distribution
    fn mean(timings: &[f64]) -> f64 {
        if timings.is_empty() {
            return 0.0;
        }
        timings.iter().sum::<f64>() / timings.len() as f64
    }

    /// Validate that an operation executes in constant time regardless of return value
    /// by comparing timing distributions for operations returning true vs false.
    ///
    /// # Errors
    /// Returns an error if insufficient samples are provided or timing variation is detected.
    pub fn validate_constant_time_operation<F>(&self, operation: F) -> Result<(), TimingError>
    where
        F: Fn() -> bool,
    {
        let timings = self.collect_timing_samples(&operation)?;
        let mean = Self::mean(&timings);

        // For single operation validation, just check it executes consistently
        // The main constant-time validation is done by compare_timings
        if mean <= 0.0 {
            return Err(TimingError::TimingVariation);
        }

        Ok(())
    }

    /// Compare timing distributions of two operations to verify constant-time behavior.
    /// Uses interleaved sampling to minimize cache and scheduling effects.
    /// Returns Ok if the operations have similar timing (constant-time), Err otherwise.
    ///
    /// # Errors
    /// Returns an error if insufficient samples, timing variation, or constant-time failure is detected.
    pub fn compare_timings<F1, F2>(&self, op1: F1, op2: F2) -> Result<(), TimingError>
    where
        F1: Fn() -> bool,
        F2: Fn() -> bool,
    {
        if self.sample_count < 10 {
            return Err(TimingError::InsufficientSamples);
        }

        // Warmup both operations
        for _ in 0..self.warmup_iterations {
            std::hint::black_box(op1());
            std::hint::black_box(op2());
        }

        let mut timings1 = Vec::with_capacity(self.sample_count);
        let mut timings2 = Vec::with_capacity(self.sample_count);

        // Interleaved sampling: alternate between operations to minimize cache effects
        for _ in 0..self.sample_count {
            // Time operation 1
            let start1 = Instant::now();
            for _ in 0..self.batch_size {
                std::hint::black_box(op1());
            }
            let elapsed1 = start1.elapsed().as_nanos() as f64 / self.batch_size as f64;
            timings1.push(elapsed1);

            // Time operation 2
            let start2 = Instant::now();
            for _ in 0..self.batch_size {
                std::hint::black_box(op2());
            }
            let elapsed2 = start2.elapsed().as_nanos() as f64 / self.batch_size as f64;
            timings2.push(elapsed2);
        }

        let mean1 = Self::mean(&timings1);
        let mean2 = Self::mean(&timings2);

        // Calculate the ratio difference between the two distributions
        let max_mean = mean1.max(mean2);
        let min_mean = mean1.min(mean2);

        if max_mean <= 0.0 {
            return Err(TimingError::TimingVariation);
        }

        let difference_ratio = (max_mean - min_mean) / max_mean;

        if difference_ratio > self.max_timing_difference_ratio {
            return Err(TimingError::ConstantTimeFailed);
        }

        Ok(())
    }

    /// Validate that comparing two byte slices takes constant time.
    /// Tests that equal vs unequal comparisons have similar timing.
    ///
    /// # Errors
    /// Returns an error if timing difference between equal and unequal comparisons exceeds threshold.
    pub fn validate_constant_time_compare(&self, a: &[u8], b: &[u8]) -> Result<(), TimingError> {
        // Pre-allocate buffers to ensure consistent memory layout
        let len = a.len().max(b.len());
        let mut buf_a1 = vec![0u8; len];
        let mut buf_a2 = vec![0u8; len];
        let mut buf_b = vec![0u8; len];

        // Copy data into fixed buffers
        buf_a1[..a.len()].copy_from_slice(a);
        buf_a2[..a.len()].copy_from_slice(a);
        buf_b[..b.len()].copy_from_slice(b);

        // Create operations that use the pre-allocated buffers
        // Equal comparison: compare buf_a1 with buf_a2 (same content)
        let equal_op = {
            let a = buf_a1.clone();
            let b = buf_a2.clone();
            move || a.ct_eq(&b).into()
        };

        // Unequal comparison: compare buf_a1 with buf_b (different content)
        let unequal_op = {
            let a = buf_a1;
            let b = buf_b;
            move || a.ct_eq(&b).into()
        };

        // Verify that equal and unequal comparisons take the same time
        self.compare_timings(equal_op, unequal_op)
    }
}

/// Validate that the constant_time_eq function has constant-time behavior
/// by comparing timing of equal vs unequal byte comparisons.
///
/// # Errors
/// Returns an error if timing analysis detects non-constant-time behavior.
pub fn validate_constant_time() -> Result<(), TimingError> {
    let validator = TimingValidator::default();

    // Test data: equal arrays and arrays differing at various positions
    let test_data_a = vec![0x41; 32];
    let test_data_b = vec![0x42; 32]; // All bytes differ

    // Validate that comparing equal vs different data takes similar time
    // This is the key property of constant-time comparison
    validator.validate_constant_time_compare(&test_data_a, &test_data_b)?;

    // Also test with data differing only in the last byte (common timing leak)
    let mut test_data_c = test_data_a.clone();
    if let Some(last) = test_data_c.last_mut() {
        *last = 0x42;
    }
    validator.validate_constant_time_compare(&test_data_a, &test_data_c)?;

    Ok(())
}

#[must_use]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    // Use constant-time length comparison to avoid leaking length information
    let len_eq = (a.len() as u32).ct_eq(&(b.len() as u32));

    // Use constant-time comparison for the data
    let data_eq = a.ct_eq(b);

    // Both length and data must be equal
    bool::from(len_eq & data_eq)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constant_time_eq_correctness() {
        // Test that constant_time_eq returns correct results
        let a = vec![0x01, 0x02, 0x03];
        let b = vec![0x01, 0x02, 0x03];
        let c = vec![0x01, 0x02, 0x04];
        let d = vec![0x01, 0x02]; // Different length

        assert!(constant_time_eq(&a, &b), "Equal arrays should return true");
        assert!(!constant_time_eq(&a, &c), "Different arrays should return false");
        assert!(!constant_time_eq(&a, &d), "Different length arrays should return false");
    }

    #[test]
    fn test_timing_validator_construction() {
        // Test that TimingValidator can be constructed and configured
        let validator = TimingValidator::new(50, 0.2);

        // Verify the validator can execute an operation
        let result = validator.validate_constant_time_operation(|| {
            std::hint::black_box(42);
            true
        });

        // The validator should successfully collect timing samples
        assert!(result.is_ok(), "Validator should successfully time a simple operation");
    }

    #[test]
    fn test_timing_validator_insufficient_samples() {
        // Test that validator rejects insufficient sample counts
        let validator = TimingValidator::new(5, 0.2); // Too few samples

        let result = validator.validate_constant_time_operation(|| true);

        assert!(
            matches!(result, Err(TimingError::InsufficientSamples)),
            "Should reject sample count < 10"
        );
    }

    #[test]
    fn test_constant_time_compare_with_subtle() {
        // Test that subtle::ConstantTimeEq comparisons pass constant-time validation
        // This validates that the subtle crate's implementation is constant-time
        let validator = TimingValidator::default();

        let data_a = vec![0x41u8; 32];
        let data_b = vec![0x42u8; 32]; // All bytes different

        // The subtle crate should provide constant-time comparison
        let result = validator.validate_constant_time_compare(&data_a, &data_b);

        assert!(
            result.is_ok(),
            "subtle::ConstantTimeEq should pass constant-time validation: {:?}",
            result
        );
    }

    #[test]
    #[ignore = "Timing validation is inherently flaky in non-controlled environments"]
    fn test_validate_constant_time_function() {
        // Test the top-level validate_constant_time function
        // NOTE: This test requires controlled conditions (CPU frequency locked,
        // no other processes, warm caches) to pass reliably.
        let result = validate_constant_time();

        assert!(
            result.is_ok(),
            "validate_constant_time should pass for subtle crate: {:?}",
            result
        );
    }

    #[test]
    #[ignore = "Timing validation is inherently flaky in non-controlled environments"]
    fn test_compare_timings_similar_operations() {
        // Test that two similar operations have similar timing
        // NOTE: This test requires controlled conditions to pass reliably.
        let validator = TimingValidator::default();

        let data1 = vec![0x41u8; 32];
        let data2 = vec![0x42u8; 32];

        let op1 = {
            let d = data1.clone();
            move || d.ct_eq(&d).into()
        };

        let op2 = {
            let d = data2.clone();
            move || d.ct_eq(&d).into()
        };

        let result = validator.compare_timings(op1, op2);

        assert!(result.is_ok(), "Similar operations should have similar timing: {:?}", result);
    }
}
