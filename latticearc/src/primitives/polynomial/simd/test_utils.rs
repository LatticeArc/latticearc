//! Shared test utilities for SIMD timing-variance tests.

#[cfg(test)]
pub(super) fn measure_timing_variance<F>(operation: F, iterations: usize) -> f64
where
    F: Fn() -> (),
{
    use std::time::Instant;

    let mut times = Vec::with_capacity(iterations);

    for _ in 0..10 {
        operation();
    }

    for _ in 0..iterations {
        let start = Instant::now();
        operation();
        let elapsed = start.elapsed();
        times.push(elapsed.as_nanos() as f64);
    }

    let mean: f64 = times.iter().sum::<f64>() / iterations as f64;
    let variance = times
        .iter()
        .map(|&t| {
            let diff = t - mean;
            diff * diff
        })
        .sum::<f64>()
        / iterations as f64;

    variance.sqrt() / mean * 100.0
}
