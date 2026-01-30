#![deny(unsafe_code)]
// Benchmark files use unwrap() for simplicity
#![allow(clippy::unwrap_used)]
// Benchmarks may use deprecated APIs for compatibility testing
#![allow(deprecated)]
// Allow fully-qualified names in benchmarks
#![allow(unused_qualifications)]
// Benchmark closures may not return values
#![allow(clippy::semicolon_if_nothing_returned)]
// Benchmark results may be unused
#![allow(unused_must_use)]

//! Performance benchmarks for LatticeArc TLS
//!
//! These benchmarks measure the performance of key TLS operations
//! to establish baseline performance metrics.

use arc_core::SecurityLevel;
use arc_tls::pq_key_exchange::PqKexMode;
use arc_tls::tls13;
use arc_tls::*;
use criterion::{Criterion, black_box, criterion_group, criterion_main};

/// Benchmark TLS configuration creation
fn bench_tls_config_creation(c: &mut Criterion) {
    c.bench_function("tls_config_creation_hybrid", |b| {
        b.iter(|| {
            let config = TlsConfig::new();
            black_box(config);
        })
    });

    c.bench_function("tls_config_creation_classic", |b| {
        b.iter(|| {
            let config = TlsConfig::new().security_level(SecurityLevel::Standard);
            black_box(config);
        })
    });

    c.bench_function("tls_config_creation_pq", |b| {
        b.iter(|| {
            let config = TlsConfig::new().security_level(SecurityLevel::Maximum);
            black_box(config);
        })
    });
}

/// Benchmark TLS 1.3 configuration conversion
fn bench_tls13_config_conversion(c: &mut Criterion) {
    let hybrid_config = TlsConfig::new();
    let classic_config = TlsConfig::new().security_level(SecurityLevel::Standard);
    let pq_config = TlsConfig::new().security_level(SecurityLevel::Maximum);

    c.bench_function("tls13_config_conversion_hybrid", |b| {
        b.iter(|| {
            let tls13_config = Tls13Config::from(&hybrid_config);
            black_box(tls13_config);
        })
    });

    c.bench_function("tls13_config_conversion_classic", |b| {
        b.iter(|| {
            let tls13_config = Tls13Config::from(&classic_config);
            black_box(tls13_config);
        })
    });

    c.bench_function("tls13_config_conversion_pq", |b| {
        b.iter(|| {
            let tls13_config = Tls13Config::from(&pq_config);
            black_box(tls13_config);
        })
    });
}

/// Benchmark key exchange provider operations
fn bench_kex_provider_operations(c: &mut Criterion) {
    c.bench_function("kex_provider_hybrid", |b| {
        b.iter(|| {
            let provider = pq_key_exchange::get_kex_provider(TlsMode::Hybrid, PqKexMode::RustlsPq);
            black_box(provider);
        })
    });

    c.bench_function("kex_provider_classic", |b| {
        b.iter(|| {
            let provider =
                pq_key_exchange::get_kex_provider(TlsMode::Classic, PqKexMode::Classical);
            black_box(provider);
        })
    });

    c.bench_function("kex_provider_pq", |b| {
        b.iter(|| {
            let provider = pq_key_exchange::get_kex_provider(TlsMode::Pq, PqKexMode::RustlsPq);
            black_box(provider);
        })
    });
}

/// Benchmark error context creation
fn bench_error_context_creation(c: &mut Criterion) {
    c.bench_function("error_context_creation", |b| {
        b.iter(|| {
            let context = ErrorContext::default();
            black_box(context);
        })
    });
}

/// Benchmark configuration validation
fn bench_config_validation(c: &mut Criterion) {
    let hybrid_config = Tls13Config::hybrid();
    let classic_config = Tls13Config::classic();
    let pq_config = Tls13Config::pq();

    c.bench_function("config_validation_hybrid", |b| {
        b.iter(|| {
            let result = tls13::verify_config(&hybrid_config);
            black_box(result);
        })
    });

    c.bench_function("config_validation_classic", |b| {
        b.iter(|| {
            let result = tls13::verify_config(&classic_config);
            black_box(result);
        })
    });

    c.bench_function("config_validation_pq", |b| {
        b.iter(|| {
            let result = tls13::verify_config(&pq_config);
            black_box(result);
        })
    });
}

/// Benchmark TLS 1.3 configuration verification
fn bench_tls13_config_verification(c: &mut Criterion) {
    let hybrid_config = Tls13Config::hybrid();
    let classic_config = Tls13Config::classic();
    let pq_config = Tls13Config::pq();

    c.bench_function("tls13_config_verification_hybrid", |b| {
        b.iter(|| {
            let result = tls13::verify_config(&hybrid_config);
            black_box(result);
        })
    });

    c.bench_function("tls13_config_verification_classic", |b| {
        b.iter(|| {
            let result = tls13::verify_config(&classic_config);
            black_box(result);
        })
    });

    c.bench_function("tls13_config_verification_pq", |b| {
        b.iter(|| {
            let result = tls13::verify_config(&pq_config);
            black_box(result);
        })
    });
}

criterion_group!(
    benches,
    bench_tls_config_creation,
    bench_tls13_config_conversion,
    bench_kex_provider_operations,
    bench_error_context_creation,
    bench_config_validation,
    bench_tls13_config_verification
);
criterion_main!(benches);
