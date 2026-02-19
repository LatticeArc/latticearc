//! Modular reduction operations for polynomial arithmetic
//!
//! Implements Montgomery and Barrett reduction for efficient modular arithmetic
//! in lattice-based cryptographic operations.

use super::constants::{MLKEM_Q, QINV};

/// Montgomery reduction: computes a * R^-1 mod q
/// where R = 2^16
#[inline(always)]
pub fn montgomery_reduce(a: i64) -> i32 {
    let t = ((a as i32).wrapping_mul(QINV)) as i64;
    let u = (a - t * MLKEM_Q as i64) >> 16;
    u as i32
}

/// Barrett reduction: computes a mod q with result in [-q/2, q/2]
#[inline(always)]
pub fn barrett_reduce(a: i32) -> i32 {
    let v = ((1i64 << 26) + (MLKEM_Q >> 1) as i64) / MLKEM_Q as i64;
    let t = ((v * a as i64 + (1i64 << 25)) >> 26) as i32;
    a - t * MLKEM_Q
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    /// Constant-time timing measurement utility
    fn measure_timing_variance<F>(operation: F, iterations: usize) -> f64
    where
        F: Fn() -> (),
    {
        let mut times = Vec::with_capacity(iterations);

        // Warm up caches
        for _ in 0..10 {
            operation();
        }

        // Measure actual timing
        for _ in 0..iterations {
            let start = Instant::now();
            operation();
            let elapsed = start.elapsed();
            times.push(elapsed.as_nanos() as f64);
        }

        // Calculate variance
        let mean: f64 = times.iter().sum::<f64>() / iterations as f64;
        let variance = times.iter()
            .map(|&t| {
                let diff = t - mean;
                diff * diff
            })
            .sum::<f64>() / iterations as f64;

        variance.sqrt() / mean * 100.0 // Coefficient of variation in percentage
    }

    #[test]
    fn test_montgomery_reduce_constant_time() {
        let test_cases = [
            0, 1, 42, 1000, 3328, 3329, 6658, 10000,
            i64::MAX / 2, i64::MIN / 2, i64::MAX, i64::MIN
        ];

        let mut results = Vec::new();

        for &input in &test_cases {
            let variance = measure_timing_variance(
                || { let _ = montgomery_reduce(input); },
                1000
            );
            results.push(variance);
        }

        for (i, &variance) in results.iter().enumerate() {
            assert!(
                variance < 10.0,
                "Montgomery reduction shows high timing variance ({:.2}%) for input {}",
                variance, test_cases[i]
            );
        }
    }

    #[test]
    fn test_barrett_reduce_constant_time() {
        let test_cases = [
            0, 1, 42, 1000, 3328, 3329, 6658, 10000,
            -1, -42, -1000, -3328, -3329, i32::MIN, i32::MAX
        ];

        let mut results = Vec::new();

        for &input in &test_cases {
            let variance = measure_timing_variance(
                || { let _ = barrett_reduce(input); },
                1000
            );
            results.push(variance);
        }

        for (i, &variance) in results.iter().enumerate() {
            assert!(
                variance < 10.0,
                "Barrett reduction shows high timing variance ({:.2}%) for input {}",
                variance, test_cases[i]
            );
        }
    }

    #[test]
    fn test_montgomery_deterministic() {
        let test_cases = [0, 1, 42, 1000, 3328, 3329, 6658, 10000];

        for &input in &test_cases {
            let result1 = montgomery_reduce(input);
            let result2 = montgomery_reduce(input);
            assert_eq!(result1, result2,
                "Montgomery reduction produces non-deterministic results for input {}", input);
        }
    }

    #[test]
    fn test_barrett_deterministic() {
        let test_cases = [0, 1, 42, 1000, 3328, 3329, -1, -42, -1000];

        for &input in &test_cases {
            let result1 = barrett_reduce(input);
            let result2 = barrett_reduce(input);
            assert_eq!(result1, result2,
                "Barrett reduction produces non-deterministic results for input {}", input);
        }
    }
}
