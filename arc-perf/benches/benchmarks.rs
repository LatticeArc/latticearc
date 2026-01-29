#![deny(unsafe_code)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

//! Criterion benchmarks for the performance module
//!
//! These benchmarks measure the overhead of performance tracking itself
//! to ensure it doesn't significantly impact production performance.

use arc_perf::{Histogram, MetricsCollector, Timer, benchmark};
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use std::hint::black_box;
use std::time::Duration;

fn bench_timer(c: &mut Criterion) {
    c.bench_function("timer_start_stop", |b| {
        b.iter(|| {
            let mut timer = Timer::start();
            black_box(timer.stop());
        });
    });

    c.bench_function("timer_elapsed", |b| {
        b.iter(|| {
            let timer = Timer::start();
            black_box(timer.elapsed());
        });
    });
}

fn bench_histogram(c: &mut Criterion) {
    let mut group = c.benchmark_group("histogram_record");

    for size in &[10, 100, 1000, 10000] {
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            let mut histogram = Histogram::new(size);
            b.iter(|| {
                histogram.record(Duration::from_nanos(black_box(size as u64)));
            });
        });
    }

    group.finish();

    c.bench_function("histogram_calculate_statistics", |b| {
        let mut histogram = Histogram::new(1000);
        for i in 0..1000 {
            histogram.record(Duration::from_nanos(i));
        }
        b.iter(|| {
            black_box(histogram.calculate_statistics());
        });
    });
}

fn bench_metrics_collector(c: &mut Criterion) {
    let mut group = c.benchmark_group("metrics_collector_record");

    for count in &[10, 100, 1000] {
        group.bench_with_input(BenchmarkId::from_parameter(count), count, |b, &count| {
            let collector = MetricsCollector::new();
            b.iter(|| {
                for _ in 0..count {
                    collector.record_operation("test", Duration::from_nanos(black_box(100)));
                }
            });
        });
    }

    group.finish();
}

fn bench_benchmark_function(c: &mut Criterion) {
    c.bench_function("benchmark_function", |b| {
        b.iter(|| {
            benchmark(100, || {
                let mut x = 0u64;
                for i in 0..100 {
                    x = x.wrapping_add(i);
                }
                // Return unit type
            });
            black_box(()); // Make closure return unit type
        });
    });
}

fn bench_overhead(c: &mut Criterion) {
    // Measure overhead of performance tracking
    c.bench_function("no_tracking", |b| {
        b.iter(|| {
            let mut x = 0u64;
            for i in 0..1000 {
                x = x.wrapping_add(i);
            }
            black_box(x);
        });
    });

    c.bench_function("with_histogram", |b| {
        let mut histogram = Histogram::new(1000);
        b.iter(|| {
            let mut x = 0u64;
            for i in 0..1000_u64 {
                histogram.record(Duration::from_nanos(i));
                x = x.wrapping_add(i);
            }
            black_box(x);
        });
    });

    c.bench_function("with_collector", |b| {
        let collector = MetricsCollector::new();
        b.iter(|| {
            let mut x = 0u64;
            for i in 0..1000_u64 {
                collector.record_operation("test", Duration::from_nanos(i));
                x = x.wrapping_add(i);
            }
            black_box(x);
        });
    });
}

criterion_group!(
    benches,
    bench_timer,
    bench_histogram,
    bench_metrics_collector,
    bench_benchmark_function,
    bench_overhead
);
criterion_main!(benches);
