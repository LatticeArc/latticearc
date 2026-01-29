#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::panic)]

//! LatticeArc Performance Primitives
//!
//! This module provides performance monitoring, benchmarking, and metrics collection
//! for cryptographic operations. It is designed to have minimal overhead when disabled
//! via the `perf` feature flag.
//!
//! # Features
//!
//! - **Timing Utilities**: Measure execution times for cryptographic operations
//! - **Histogram/Percentile**: Compute latency distribution statistics
//! - **Metrics Collection**: Track operation counts, timings, and resource usage
//! - **Optional Overhead**: Zero overhead when disabled (compile-time feature flag)
//!
//! # Usage
//!
//! Enable the `perf` feature in `Cargo.toml`:
//!
//! ```toml
//! [dependencies]
//! latticearc = { version = "1.0.0", features = ["perf"] }
//! ```
//!
//! # Example
//!
//! ```rust,no_run
//! use arc_perf::{Timer, MetricsCollector};
//!
//! // Measure execution time of an operation
//! let mut timer = Timer::start();
//! // ... perform cryptographic operation ...
//! let duration = timer.stop();
//!
//! // Collect metrics over multiple operations
//! let mut collector = MetricsCollector::new();
//! collector.record_operation("keygen", duration);
//! collector.record_operation("encrypt", duration);
//!
//! // Get statistics
//! let stats = collector.get_statistics("keygen");
//! println!("Average: {:?}", stats.average);
//! println!("P99: {:?}", stats.percentile_99);
//! ```

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// A simple high-resolution timer for measuring execution time
#[derive(Debug, Clone, Copy)]
pub struct Timer {
    start_time: Option<Instant>,
    elapsed: Duration,
}

impl Timer {
    /// Create a new timer that starts immediately
    #[inline]
    #[must_use]
    pub fn start() -> Self {
        Self { start_time: Some(Instant::now()), elapsed: Duration::ZERO }
    }

    /// Create a new timer that is not yet started
    #[inline]
    #[must_use]
    pub fn new() -> Self {
        Self { start_time: None, elapsed: Duration::ZERO }
    }

    /// Start the timer (or restart if already running)
    #[inline]
    pub fn start_now(&mut self) {
        self.start_time = Some(Instant::now());
        self.elapsed = Duration::ZERO;
    }

    /// Stop the timer and return the elapsed duration
    #[inline]
    pub fn stop(&mut self) -> Duration {
        if let Some(start) = self.start_time.take() {
            self.elapsed = start.elapsed();
        }
        self.elapsed
    }

    /// Get the current elapsed duration without stopping the timer
    #[inline]
    #[must_use]
    pub fn elapsed(&self) -> Duration {
        if let Some(start) = self.start_time { start.elapsed() } else { self.elapsed }
    }

    /// Check if the timer is currently running
    #[inline]
    #[must_use]
    pub fn is_running(&self) -> bool {
        self.start_time.is_some()
    }
}

impl Default for Timer {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics for a set of timing measurements
#[derive(Debug, Clone)]
pub struct TimingStatistics {
    /// Number of samples
    pub count: usize,
    /// Minimum duration
    pub min: Duration,
    /// Maximum duration
    pub max: Duration,
    /// Average duration
    pub average: Duration,
    /// Median duration
    pub median: Duration,
    /// 90th percentile
    pub percentile_90: Duration,
    /// 95th percentile
    pub percentile_95: Duration,
    /// 99th percentile
    pub percentile_99: Duration,
    /// Standard deviation
    pub std_dev: Duration,
}

impl TimingStatistics {
    /// Create empty statistics
    #[must_use]
    pub fn empty() -> Self {
        Self {
            count: 0,
            min: Duration::ZERO,
            max: Duration::ZERO,
            average: Duration::ZERO,
            median: Duration::ZERO,
            percentile_90: Duration::ZERO,
            percentile_95: Duration::ZERO,
            percentile_99: Duration::ZERO,
            std_dev: Duration::ZERO,
        }
    }
}

impl Default for TimingStatistics {
    fn default() -> Self {
        Self::empty()
    }
}

/// Histogram for collecting and analyzing timing distributions
#[derive(Debug, Clone)]
pub struct Histogram {
    samples: Vec<u128>, // stored as nanoseconds
}

impl Histogram {
    /// Create a new empty histogram with pre-allocated capacity
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self { samples: Vec::with_capacity(capacity) }
    }

    /// Create a new empty histogram
    #[must_use]
    pub fn new_default() -> Self {
        Self::new(100)
    }

    /// Record a timing sample
    pub fn record(&mut self, duration: Duration) {
        self.samples.push(duration.as_nanos());
    }

    /// Record multiple timing samples
    pub fn record_batch(&mut self, durations: &[Duration]) {
        self.samples.reserve(durations.len());
        for &duration in durations {
            self.samples.push(duration.as_nanos());
        }
    }

    /// Get the number of samples
    #[must_use]
    pub fn count(&self) -> usize {
        self.samples.len()
    }

    /// Clear all samples
    pub fn clear(&mut self) {
        self.samples.clear();
    }

    /// Calculate statistics for the collected samples
    #[allow(clippy::arithmetic_side_effects)]
    #[allow(clippy::cast_possible_truncation)]
    #[allow(clippy::cast_precision_loss)]
    #[allow(clippy::cast_sign_loss)]
    #[allow(clippy::cast_lossless)]
    #[must_use]
    pub fn calculate_statistics(&self) -> TimingStatistics {
        if self.samples.is_empty() {
            return TimingStatistics::empty();
        }

        let mut sorted = self.samples.clone();
        sorted.sort_unstable();

        let count = sorted.len();
        let min = Duration::from_nanos(
            sorted.first().copied().and_then(|x| u64::try_from(x).ok()).unwrap_or(0),
        );
        let max = Duration::from_nanos(
            sorted
                .get(count.saturating_sub(1))
                .copied()
                .and_then(|x| u64::try_from(x).ok())
                .unwrap_or(0),
        );
        let sum: u128 = sorted.iter().sum();
        let average = if count > 0 {
            Duration::from_nanos(
                u64::try_from(sum / u128::try_from(count).unwrap_or(1)).unwrap_or(0),
            )
        } else {
            Duration::ZERO
        };

        // Calculate median
        let median = if count.is_multiple_of(2) {
            let half_count = count / 2;
            let mid_left = sorted.get(half_count.saturating_sub(1)).copied().unwrap_or(0);
            let mid_right = sorted.get(half_count).copied().unwrap_or(0);
            Duration::from_nanos(u64::try_from((mid_left + mid_right) / 2).unwrap_or(0))
        } else {
            let half_count = count / 2;
            Duration::from_nanos(
                u64::try_from(sorted.get(half_count).copied().unwrap_or(0)).unwrap_or(0),
            )
        };

        // Calculate percentiles
        let percentile_90 = Self::percentile(&sorted, 90.0);
        let percentile_95 = Self::percentile(&sorted, 95.0);
        let percentile_99 = Self::percentile(&sorted, 99.0);

        // Calculate standard deviation
        let mean = if average.as_nanos() <= f64::MAX.to_bits() as u128 {
            f64::from_bits(average.as_nanos() as u64)
        } else {
            0.0
        };
        let variance = if count > 0 {
            sorted
                .iter()
                .map(|&x| {
                    let x_f64 = if x <= f64::MAX.to_bits() as u128 {
                        f64::from_bits(x as u64)
                    } else {
                        0.0
                    };
                    let diff = x_f64 - mean;
                    diff * diff
                })
                .sum::<f64>()
                / count as f64
        } else {
            0.0
        };
        let std_dev = Duration::from_nanos(variance.sqrt().to_bits());

        TimingStatistics {
            count,
            min,
            max,
            average,
            median,
            percentile_90,
            percentile_95,
            percentile_99,
            std_dev,
        }
    }

    /// Calculate a specific percentile
    #[allow(clippy::cast_possible_truncation)]
    #[allow(clippy::cast_precision_loss)]
    #[allow(clippy::cast_sign_loss)]
    fn percentile(sorted: &[u128], percentile: f64) -> Duration {
        if sorted.is_empty() {
            return Duration::ZERO;
        }

        let len = sorted.len();
        let float_index = (percentile / 100.0) * (len.saturating_sub(1) as f64);
        let index = float_index as usize;
        let safe_index = index.min(len.saturating_sub(1));
        Duration::from_nanos(
            sorted.get(safe_index).copied().and_then(|x| u64::try_from(x).ok()).unwrap_or(0),
        )
    }

    /// Merge another histogram into this one
    pub fn merge(&mut self, other: &Histogram) {
        self.samples.extend_from_slice(&other.samples);
    }
}

/// A thread-safe collector for performance metrics
pub struct MetricsCollector {
    histograms: Arc<Mutex<HashMap<String, Histogram>>>,
    operation_counts: Arc<Mutex<HashMap<String, usize>>>,
}

impl MetricsCollector {
    /// Create a new metrics collector
    #[must_use]
    pub fn new() -> Self {
        Self {
            histograms: Arc::new(Mutex::new(HashMap::new())),
            operation_counts: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Record a single operation timing
    #[allow(clippy::arithmetic_side_effects)]
    pub fn record_operation(&self, name: &str, duration: Duration) {
        if let Ok(mut histograms) = self.histograms.lock() {
            histograms
                .entry(name.to_string())
                .or_insert_with(Histogram::new_default)
                .record(duration);
        }

        if let Ok(mut counts) = self.operation_counts.lock() {
            let current_count = counts.entry(name.to_string()).or_insert(0);
            *current_count = current_count.saturating_add(1);
        }
    }

    /// Get statistics for a specific operation
    pub fn get_statistics(&self, name: &str) -> TimingStatistics {
        if let Ok(histograms) = self.histograms.lock() {
            histograms
                .get(name)
                .map(Histogram::calculate_statistics)
                .unwrap_or_else(TimingStatistics::empty)
        } else {
            TimingStatistics::empty()
        }
    }

    /// Get the total count for a specific operation
    #[must_use]
    pub fn get_count(&self, name: &str) -> usize {
        if let Ok(counts) = self.operation_counts.lock() {
            *counts.get(name).unwrap_or(&0)
        } else {
            0
        }
    }

    /// Get all operation names
    #[must_use]
    pub fn operation_names(&self) -> Vec<String> {
        if let Ok(histograms) = self.histograms.lock() {
            histograms.keys().cloned().collect()
        } else {
            Vec::new()
        }
    }

    /// Get all statistics
    #[must_use]
    pub fn get_all_statistics(&self) -> HashMap<String, TimingStatistics> {
        if let Ok(histograms) = self.histograms.lock() {
            histograms.iter().map(|(name, h)| (name.clone(), h.calculate_statistics())).collect()
        } else {
            HashMap::new()
        }
    }

    /// Clear all collected metrics
    pub fn clear(&self) {
        if let Ok(mut histograms) = self.histograms.lock() {
            histograms.clear();
        }

        if let Ok(mut counts) = self.operation_counts.lock() {
            counts.clear();
        }
    }

    /// Create a clone of the collector that shares the same underlying data
    #[must_use]
    pub fn clone_collector(&self) -> Self {
        Self {
            histograms: Arc::clone(&self.histograms),
            operation_counts: Arc::clone(&self.operation_counts),
        }
    }
}

impl Default for MetricsCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for MetricsCollector {
    fn clone(&self) -> Self {
        self.clone_collector()
    }
}

/// RAII-style timer that automatically records to a metrics collector
pub struct ScopedTimer<'a> {
    timer: Timer,
    collector: Option<&'a MetricsCollector>,
    operation_name: Option<&'a str>,
}

impl<'a> ScopedTimer<'a> {
    /// Create a new scoped timer that records to the collector when dropped
    #[must_use]
    pub fn new(collector: &'a MetricsCollector, operation_name: &'a str) -> Self {
        Self {
            timer: Timer::start(),
            collector: Some(collector),
            operation_name: Some(operation_name),
        }
    }

    /// Create a new scoped timer without a collector (timing only)
    #[must_use]
    pub fn timing_only() -> Self {
        Self { timer: Timer::start(), collector: None, operation_name: None }
    }

    /// Stop the timer and get the elapsed duration
    #[must_use]
    pub fn stop(mut self) -> Duration {
        let duration = self.timer.stop();
        if let (Some(collector), Some(name)) = (self.collector, self.operation_name) {
            collector.record_operation(name, duration);
        }
        duration
    }

    /// Get the current elapsed duration without stopping
    #[must_use]
    pub fn elapsed(&self) -> Duration {
        self.timer.elapsed()
    }
}

impl<'a> Drop for ScopedTimer<'a> {
    fn drop(&mut self) {
        if let (Some(collector), Some(name)) = (self.collector, self.operation_name)
            && self.timer.is_running()
        {
            let duration = self.timer.stop();
            collector.record_operation(name, duration);
        }
    }
}

/// Benchmark helper for running an operation multiple times
pub fn benchmark<F>(iterations: usize, operation: F) -> TimingStatistics
where
    F: Fn(),
{
    let mut histogram = Histogram::new(iterations);

    // Warm-up phase
    for _ in 0..10.min(iterations / 10) {
        operation();
    }

    // Benchmark phase
    for _ in 0..iterations {
        let mut timer = Timer::start();
        operation();
        histogram.record(timer.stop());
    }

    histogram.calculate_statistics()
}

/// Helper to time a single operation
pub fn time_operation<F>(operation: F) -> Duration
where
    F: FnOnce(),
{
    let mut timer = Timer::start();
    operation();
    timer.stop()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timer_basic() {
        let mut timer = Timer::new();
        assert!(!timer.is_running());

        timer.start_now();
        assert!(timer.is_running());

        std::thread::sleep(Duration::from_millis(10));
        let elapsed = timer.stop();
        assert!(!timer.is_running());
        assert!(elapsed >= Duration::from_millis(10));
    }

    #[test]
    fn test_timer_elapsed_while_running() {
        let timer = Timer::start();
        std::thread::sleep(Duration::from_millis(5));
        let elapsed = timer.elapsed();
        assert!(elapsed >= Duration::from_millis(5));
        assert!(timer.is_running());
    }

    #[test]
    fn test_histogram_basic() {
        let mut histogram = Histogram::new(10);
        histogram.record(Duration::from_millis(10));
        histogram.record(Duration::from_millis(20));
        histogram.record(Duration::from_millis(30));

        assert_eq!(histogram.count(), 3);

        let stats = histogram.calculate_statistics();
        assert_eq!(stats.count, 3);
        assert_eq!(stats.min, Duration::from_millis(10));
        assert_eq!(stats.max, Duration::from_millis(30));
        assert_eq!(stats.median, Duration::from_millis(20));
    }

    #[test]
    fn test_histogram_empty() {
        let histogram = Histogram::new(10);
        let stats = histogram.calculate_statistics();
        assert_eq!(stats.count, 0);
        assert_eq!(stats.min, Duration::ZERO);
    }

    #[test]
    fn test_histogram_merge() {
        let mut hist1 = Histogram::new(5);
        hist1.record(Duration::from_millis(10));
        hist1.record(Duration::from_millis(20));

        let mut hist2 = Histogram::new(5);
        hist2.record(Duration::from_millis(30));
        hist2.record(Duration::from_millis(40));

        hist1.merge(&hist2);
        assert_eq!(hist1.count(), 4);

        let stats = hist1.calculate_statistics();
        assert_eq!(stats.min, Duration::from_millis(10));
        assert_eq!(stats.max, Duration::from_millis(40));
    }

    #[test]
    fn test_metrics_collector() {
        let collector = MetricsCollector::new();

        collector.record_operation("test", Duration::from_millis(10));
        collector.record_operation("test", Duration::from_millis(20));
        collector.record_operation("other", Duration::from_millis(30));

        assert_eq!(collector.get_count("test"), 2);
        assert_eq!(collector.get_count("other"), 1);

        let stats = collector.get_statistics("test");
        assert_eq!(stats.count, 2);
        assert_eq!(stats.min, Duration::from_millis(10));
        assert_eq!(stats.max, Duration::from_millis(20));
    }

    #[test]
    fn test_metrics_collector_clone() {
        let collector1 = MetricsCollector::new();
        let collector2 = collector1.clone();

        collector1.record_operation("test", Duration::from_millis(10));
        assert_eq!(collector2.get_count("test"), 1);
    }

    #[test]
    fn test_benchmark() {
        let stats = benchmark(100, || {
            // Simple operation
            let _ = 1 + 1;
        });

        assert_eq!(stats.count, 100);
        assert!(stats.average > Duration::ZERO);
        assert!(stats.min <= stats.average);
        assert!(stats.max >= stats.average);
    }

    #[test]
    fn test_time_operation() {
        let duration = time_operation(|| {
            std::thread::sleep(Duration::from_millis(5));
        });

        assert!(duration >= Duration::from_millis(5));
    }

    #[test]
    fn test_scoped_timer_basic() {
        let collector = MetricsCollector::new();

        {
            let _timer = ScopedTimer::new(&collector, "test_operation");
            std::thread::sleep(Duration::from_millis(5));
        }

        assert_eq!(collector.get_count("test_operation"), 1);
        let stats = collector.get_statistics("test_operation");
        assert!(stats.average >= Duration::from_millis(5));
    }

    #[test]
    fn test_scoped_timer_timing_only() {
        let timer = ScopedTimer::timing_only();
        std::thread::sleep(Duration::from_millis(5));
        let elapsed = timer.elapsed();
        assert!(elapsed >= Duration::from_millis(5));
    }

    #[test]
    fn test_percentile_calculation() {
        let mut histogram = Histogram::new(100);

        // Add samples from 0 to 99 nanoseconds
        for i in 0..100 {
            histogram.record(Duration::from_nanos(i));
        }

        let stats = histogram.calculate_statistics();

        // P50 should be close to 50ns
        assert!(stats.median.as_nanos() >= 45 && stats.median.as_nanos() <= 55);

        // P90 should be close to 90ns
        assert!(stats.percentile_90.as_nanos() >= 85 && stats.percentile_90.as_nanos() <= 95);

        // P99 should be close to 99ns
        assert!(stats.percentile_99.as_nanos() >= 95 && stats.percentile_99.as_nanos() <= 99);
    }

    #[test]
    fn test_timing_statistics_default() {
        let stats = TimingStatistics::default();
        assert_eq!(stats.count, 0);
        assert_eq!(stats.min, Duration::ZERO);
        assert_eq!(stats.max, Duration::ZERO);
    }

    #[test]
    fn test_histogram_clear() {
        let mut histogram = Histogram::new(10);
        histogram.record(Duration::from_millis(10));
        histogram.record(Duration::from_millis(20));

        assert_eq!(histogram.count(), 2);

        histogram.clear();
        assert_eq!(histogram.count(), 0);
    }

    #[test]
    fn test_metrics_collector_clear() {
        let collector = MetricsCollector::new();
        collector.record_operation("test", Duration::from_millis(10));
        collector.record_operation("other", Duration::from_millis(20));

        assert_eq!(collector.get_count("test"), 1);
        assert_eq!(collector.get_count("other"), 1);

        collector.clear();

        assert_eq!(collector.get_count("test"), 0);
        assert_eq!(collector.get_count("other"), 0);
        assert!(collector.operation_names().is_empty());
    }
}
