# LatticeArc Performance Primitives

The `arc-perf` crate provides performance monitoring, benchmarking, and metrics collection utilities for LatticeArc cryptographic operations.

## Features

- **Timing Utilities**: High-resolution timers for measuring execution time
- **Histogram/Percentile**: Compute latency distribution statistics (P50, P90, P95, P99)
- **Metrics Collection**: Track operation counts, timings, and resource usage
- **Thread-Safe**: All collectors can be used safely across multiple threads
- **Optional Overhead**: Zero overhead when disabled (via compile-time feature flag)

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
latticearc = { version = "1.0.0", features = ["perf"] }
```

Or use the perf crate directly:

```toml
[dependencies]
arc-perf = "1.0.0"
```

## Usage

### Basic Timing

```rust
use latticearc_perf::Timer;

let mut timer = Timer::start();
// ... perform cryptographic operation ...
let duration = timer.stop();
println!("Operation took {:?}", duration);
```

### Metrics Collection

```rust
use latticearc_perf::{MetricsCollector, Timer};
use std::time::Duration;

let collector = MetricsCollector::new();

// Record multiple operations
for _ in 0..100 {
    let timer = Timer::start();
    // ... cryptographic operation ...
    let duration = timer.stop();
    collector.record_operation("keygen", duration);
}

// Get statistics
let stats = collector.get_statistics("keygen");
println!("Average: {:?}", stats.average);
println!("P99: {:?}", stats.percentile_99);
println!("Count: {}", stats.count);
```

### Scoped Timer (RAII)

```rust
use latticearc_perf::{MetricsCollector, ScopedTimer};

let collector = MetricsCollector::new();

{
    let _timer = ScopedTimer::new(&collector, "encrypt_operation");
    // ... perform encryption ...
    // Timer automatically records when it goes out of scope
}

// Metrics are recorded
assert_eq!(collector.get_count("encrypt_operation"), 1);
```

### Histogram Analysis

```rust
use latticearc_perf::{Histogram, Timer};
use std::time::Duration;

let mut histogram = Histogram::new(1000);

// Collect samples
for _ in 0..1000 {
    let timer = Timer::start();
    // ... operation ...
    histogram.record(timer.stop());
}

// Calculate statistics
let stats = histogram.calculate_statistics();
println!("Min: {:?}", stats.min);
println!("Max: {:?}", stats.max);
println!("Average: {:?}", stats.average);
println!("Median: {:?}", stats.median);
println!("P90: {:?}", stats.percentile_90);
println!("P95: {:?}", stats.percentile_95);
println!("P99: {:?}", stats.percentile_99);
println!("Std Dev: {:?}", stats.std_dev);
```

### Benchmark Helper

```rust
use latticearc_perf::benchmark;

let stats = benchmark(1000, || {
    // Operation to benchmark
    let mut x = 0u64;
    for i in 0..100 {
        x = x.wrapping_add(i);
    }
    x
});

println!("Average: {:?}", stats.average);
println!("Throughput: {:.1} ops/sec", 1000.0 / stats.average.as_secs_f64());
```

## API Overview

### `Timer`

A simple high-resolution timer for measuring execution time.

- `Timer::start()` - Start a new timer
- `Timer::new()` - Create a new timer (not started)
- `timer.start_now()` - Start the timer
- `timer.stop()` - Stop the timer and return elapsed time
- `timer.elapsed()` - Get current elapsed time without stopping
- `timer.is_running()` - Check if timer is running

### `Histogram`

Collects timing samples and calculates statistics.

- `Histogram::new(capacity)` - Create a new histogram
- `histogram.record(duration)` - Record a single sample
- `histogram.record_batch(durations)` - Record multiple samples
- `histogram.calculate_statistics()` - Compute all statistics
- `histogram.clear()` - Clear all samples
- `histogram.merge(&other)` - Merge another histogram

### `MetricsCollector`

Thread-safe collector for performance metrics.

- `MetricsCollector::new()` - Create a new collector
- `collector.record_operation(name, duration)` - Record an operation
- `collector.get_statistics(name)` - Get statistics for an operation
- `collector.get_count(name)` - Get operation count
- `collector.get_all_statistics()` - Get all statistics
- `collector.clear()` - Clear all metrics

### `ScopedTimer`

RAII-style timer that automatically records to a collector.

- `ScopedTimer::new(collector, operation_name)` - Create with collector
- `ScopedTimer::timing_only()` - Create without collector
- `timer.elapsed()` - Get current elapsed time

### Helper Functions

- `benchmark(iterations, operation)` - Run an operation multiple times
- `time_operation(operation)` - Time a single operation

## Performance Considerations

- The performance module has minimal overhead when used correctly
- Collecting metrics adds a small overhead (~50-100ns per operation)
- For production use, consider enabling collection only during debugging or when specifically needed
- Use feature flags to completely disable performance tracking when not needed

## Testing

Run tests:

```bash
cargo test -p perf
```

Run benchmarks:

```bash
cargo bench -p perf
```

## External Monitoring

For production monitoring, consider using external tools instead of built-in tracking:

- **Prometheus** + **OpenTelemetry** - Metrics collection and monitoring
- **Flamegraph** - Performance profiling and visualization
- **perf (Linux)** - CPU profiling
- **dtrace** - System tracing (macOS/BSD)

## License

Apache License 2.0
