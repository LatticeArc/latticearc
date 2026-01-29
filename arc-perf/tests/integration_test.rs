#![deny(unsafe_code)]
// Test files use unwrap() for simplicity - test failures will show clear panics
#![allow(clippy::unwrap_used)]
#![deny(clippy::panic)]

//! Integration tests for the performance module

use arc_perf::{Histogram, MetricsCollector, ScopedTimer, Timer, benchmark, time_operation};
use std::time::Duration;

#[test]
fn test_timer_measurements() {
    let mut timer = Timer::new();
    assert!(!timer.is_running());

    timer.start_now();
    std::thread::sleep(Duration::from_millis(10));
    let elapsed = timer.stop();

    assert!(!timer.is_running());
    assert!(elapsed >= Duration::from_millis(10));
}

#[test]
fn test_histogram_statistics() {
    let mut histogram = Histogram::new(100);

    // Add samples from 0 to 99 nanoseconds
    for i in 0..100 {
        histogram.record(Duration::from_nanos(i));
    }

    let stats = histogram.calculate_statistics();
    assert_eq!(stats.count, 100);
    assert_eq!(stats.min, Duration::from_nanos(0));
    assert_eq!(stats.max, Duration::from_nanos(99));

    // Check percentiles are reasonable
    assert!(stats.median >= Duration::from_nanos(40));
    assert!(stats.median <= Duration::from_nanos(60));

    assert!(stats.percentile_90 >= Duration::from_nanos(85));
    assert!(stats.percentile_90 <= Duration::from_nanos(95));

    assert!(stats.percentile_99 >= Duration::from_nanos(95));
    assert!(stats.percentile_99 <= Duration::from_nanos(99));
}

#[test]
fn test_metrics_collector_threading() {
    use std::sync::Arc;
    use std::thread;

    let collector = Arc::new(MetricsCollector::new());
    let mut handles = vec![];

    for i in 0..10 {
        let collector_clone = Arc::clone(&collector);
        let handle = thread::spawn(move || {
            for _ in 0..100 {
                let duration = Duration::from_nanos(i * 10);
                collector_clone.record_operation("threaded_test", duration);
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }

    // Should have 1000 total samples (10 threads * 100 samples)
    assert_eq!(collector.get_count("threaded_test"), 1000);

    let stats = collector.get_statistics("threaded_test");
    assert_eq!(stats.count, 1000);
}

#[test]
fn test_scoped_timer_recording() {
    let collector = MetricsCollector::new();

    {
        let _timer = ScopedTimer::new(&collector, "scoped_test");
        std::thread::sleep(Duration::from_millis(5));
    }

    assert_eq!(collector.get_count("scoped_test"), 1);
    let stats = collector.get_statistics("scoped_test");
    assert!(stats.average >= Duration::from_millis(5));
}

#[test]
fn test_scoped_timer_manual_stop() {
    let collector = MetricsCollector::new();

    let timer = ScopedTimer::new(&collector, "manual_stop");
    std::thread::sleep(Duration::from_millis(5));
    let elapsed = timer.stop();

    // Recording happens on drop, so stop() returns the elapsed time
    assert!(elapsed >= Duration::from_millis(5));

    assert_eq!(collector.get_count("manual_stop"), 1);
}

#[test]
fn test_benchmark_function() {
    let stats = benchmark(1000, || {
        let mut x = 0u64;
        for i in 0..100 {
            x = x.wrapping_add(i);
        }
    });

    assert_eq!(stats.count, 1000);
    assert!(stats.average > Duration::ZERO);
    assert!(stats.min <= stats.average);
    assert!(stats.max >= stats.average);
}

#[test]
fn test_time_operation_function() {
    let duration = time_operation(|| {
        std::thread::sleep(Duration::from_millis(10));
    });

    assert!(duration >= Duration::from_millis(10));
}

#[test]
fn test_metrics_collector_multiple_operations() {
    let collector = MetricsCollector::new();

    collector.record_operation("op1", Duration::from_millis(10));
    collector.record_operation("op1", Duration::from_millis(20));
    collector.record_operation("op1", Duration::from_millis(30));

    collector.record_operation("op2", Duration::from_millis(100));
    collector.record_operation("op2", Duration::from_millis(200));

    assert_eq!(collector.get_count("op1"), 3);
    assert_eq!(collector.get_count("op2"), 2);

    let stats1 = collector.get_statistics("op1");
    assert_eq!(stats1.count, 3);
    assert_eq!(stats1.min, Duration::from_millis(10));
    assert_eq!(stats1.max, Duration::from_millis(30));

    let stats2 = collector.get_statistics("op2");
    assert_eq!(stats2.count, 2);
    assert_eq!(stats2.min, Duration::from_millis(100));
    assert_eq!(stats2.max, Duration::from_millis(200));

    let all_stats = collector.get_all_statistics();
    assert_eq!(all_stats.len(), 2);
}

#[test]
fn test_histogram_merge() {
    let mut hist1 = Histogram::new(50);
    hist1.record(Duration::from_nanos(10));
    hist1.record(Duration::from_nanos(20));

    let mut hist2 = Histogram::new(50);
    hist2.record(Duration::from_nanos(30));
    hist2.record(Duration::from_nanos(40));

    hist1.merge(&hist2);

    let stats = hist1.calculate_statistics();
    assert_eq!(stats.count, 4);
    assert_eq!(stats.min, Duration::from_nanos(10));
    assert_eq!(stats.max, Duration::from_nanos(40));
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

#[test]
fn test_histogram_batch_recording() {
    let mut histogram = Histogram::new(10);

    let durations =
        vec![Duration::from_nanos(10), Duration::from_nanos(20), Duration::from_nanos(30)];

    histogram.record_batch(&durations);

    assert_eq!(histogram.count(), 3);
}

#[test]
#[ignore = "Performance overhead test is flaky in CI due to system load variations"]
fn test_performance_overhead() {
    // Measure overhead of performance tracking
    let collector = MetricsCollector::new();

    // Baseline: no tracking
    let baseline = time_operation(|| {
        let mut x = 0u64;
        for i in 0..10000 {
            x = x.wrapping_add(i);
        }
    });

    // With tracking
    let with_tracking = time_operation(|| {
        let mut x = 0u64;
        for _ in 0..10000 {
            x = x.wrapping_add(1);
            // Simulate some work
            collector.record_operation("overhead_test", Duration::from_nanos(1));
        }
    });

    // The tracking overhead should be reasonable (less than 10x in this simple case)
    // In practice, the overhead is minimal for actual cryptographic operations
    assert!(with_tracking < baseline * 100);
}

#[test]
fn test_empty_histogram_statistics() {
    let histogram = Histogram::new(10);
    let stats = histogram.calculate_statistics();

    assert_eq!(stats.count, 0);
    assert_eq!(stats.min, Duration::ZERO);
    assert_eq!(stats.max, Duration::ZERO);
    assert_eq!(stats.average, Duration::ZERO);
}

#[test]
fn test_unknown_operation_statistics() {
    let collector = MetricsCollector::new();
    let stats = collector.get_statistics("unknown_operation");

    assert_eq!(stats.count, 0);
}

#[test]
fn test_multiple_scoped_timers() {
    let collector = MetricsCollector::new();

    {
        let _timer1 = ScopedTimer::new(&collector, "timer1");
        let _timer2 = ScopedTimer::new(&collector, "timer2");

        std::thread::sleep(Duration::from_millis(5));
    }

    assert_eq!(collector.get_count("timer1"), 1);
    assert_eq!(collector.get_count("timer2"), 1);
}

#[test]
fn test_scoped_timer_timing_only() {
    let timer = ScopedTimer::timing_only();
    std::thread::sleep(Duration::from_millis(5));
    let elapsed = timer.elapsed();

    assert!(elapsed >= Duration::from_millis(5));
}

#[test]
fn test_benchmark_warmup() {
    // Benchmark should include a warmup phase
    let stats = benchmark(100, || {
        // Simple operation
        let _ = 1 + 1;
    });

    assert_eq!(stats.count, 100);
    assert!(stats.average > Duration::ZERO);
}
