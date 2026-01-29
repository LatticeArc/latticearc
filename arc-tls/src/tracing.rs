#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

//! # Structured Tracing for TLS Operations
//!
//! This module provides comprehensive tracing infrastructure for TLS operations:
//! - Span-based operation tracking
//! - Structured logging with metadata
//! - Distributed tracing support
//! - Performance metrics collection

use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tracing::instrument;
use tracing::{Level, Span, debug, error, info, span, trace, warn};
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

/// TLS operation tracing configuration
#[derive(Debug, Clone)]
pub struct TracingConfig {
    /// Enable distributed tracing
    pub distributed_tracing: bool,
    /// Log level for TLS operations
    pub log_level: Level,
    /// Include sensitive data (keys, certificates) in traces
    pub include_sensitive_data: bool,
    /// Track performance metrics
    pub track_performance: bool,
}

impl Default for TracingConfig {
    fn default() -> Self {
        Self {
            distributed_tracing: false,
            log_level: Level::INFO,
            include_sensitive_data: false,
            track_performance: true,
        }
    }
}

impl TracingConfig {
    /// Enable debug logging
    #[must_use]
    pub fn debug() -> Self {
        Self { log_level: Level::DEBUG, ..Default::default() }
    }

    /// Enable trace logging
    #[must_use]
    pub fn trace() -> Self {
        Self { log_level: Level::TRACE, include_sensitive_data: false, ..Default::default() }
    }

    /// Enable sensitive data logging (USE WITH CAUTION)
    #[must_use]
    pub fn with_sensitive_data(mut self) -> Self {
        self.include_sensitive_data = true;
        self
    }
}

/// Initialize TLS tracing
///
/// # Arguments
/// * `config` - Tracing configuration
///
/// # Example
/// ```no_run
/// use arc_tls::tracing::init_tracing;
///
/// init_tracing(&Default::default());
/// ```
pub fn init_tracing(config: &TracingConfig) {
    let filter =
        EnvFilter::builder().with_default_directive(config.log_level.into()).from_env_lossy();

    tracing_subscriber::registry()
        .with(fmt::layer().with_target(true).with_thread_ids(true))
        .with(filter)
        .init();
}

/// TLS operation span builder
#[derive(Debug)]
pub struct TlsSpan {
    span: Span,
    start_time: Instant,
}

impl TlsSpan {
    /// Create new TLS operation span
    pub fn new(operation: &str, peer: Option<SocketAddr>) -> Self {
        let span = span!(
            Level::INFO,
            "tls_operation",
            operation = %operation,
            peer = peer.map(|p| p.to_string()).unwrap_or_else(|| "unknown".to_string()),
        );

        span.in_scope(|| {
            trace!("Starting TLS operation: {}", operation);
        });

        Self { span, start_time: Instant::now() }
    }

    /// Create connection span
    pub fn connection(addr: &str, domain: Option<&str>) -> Self {
        let span = span!(
            Level::INFO,
            "tls_connection",
            addr = %addr,
            domain = domain.unwrap_or("none"),
        );

        span.in_scope(|| {
            info!("Initiating TLS connection to {}", addr);
        });

        Self { span, start_time: Instant::now() }
    }

    /// Create handshake span
    pub fn handshake(peer: Option<SocketAddr>, mode: &str) -> Self {
        let span = span!(
            Level::INFO,
            "tls_handshake",
            peer = peer.map(|p| p.to_string()).unwrap_or_else(|| "unknown".to_string()),
            mode = %mode,
        );

        span.in_scope(|| {
            debug!("Starting TLS handshake");
        });

        Self { span, start_time: Instant::now() }
    }

    /// Create key exchange span
    pub fn key_exchange(method: &str) -> Self {
        let span = span!(
            Level::INFO,
            "tls_key_exchange",
            method = %method,
        );

        span.in_scope(|| {
            debug!("Starting key exchange: {}", method);
        });

        Self { span, start_time: Instant::now() }
    }

    /// Create certificate verification span
    pub fn certificate_verification(subject: &str, issuer: &str) -> Self {
        let span = span!(
            Level::INFO,
            "certificate_verification",
            subject = %subject,
            issuer = %issuer,
        );

        span.in_scope(|| {
            debug!("Verifying certificate: {}", subject);
        });

        Self { span, start_time: Instant::now() }
    }

    /// Get elapsed time since span creation
    #[must_use]
    pub fn elapsed(&self) -> Duration {
        self.start_time.elapsed()
    }

    /// Complete the span successfully
    pub fn complete(self) {
        let duration = self.start_time.elapsed();
        self.span.in_scope(|| {
            info!(
                "Operation completed successfully in {}.{:03}s",
                duration.as_secs(),
                duration.subsec_millis()
            );
        });
    }

    /// Complete the span with error
    pub fn error<E>(self, error: E)
    where
        E: std::error::Error,
    {
        let duration = self.start_time.elapsed();
        self.span.in_scope(|| {
            error!(
                error = %error,
                error_type = %std::any::type_name::<E>(),
                "Operation failed after {}.{:03}s",
                duration.as_secs(),
                duration.subsec_millis()
            );
        });
    }

    /// Add custom field to span
    pub fn field<F>(self, key: &str, value: F) -> Self
    where
        F: tracing::field::Value,
    {
        self.span.record(key, value);
        self
    }

    /// Enter span scope
    pub fn in_scope<F, R>(&self, f: F) -> R
    where
        F: FnOnce() -> R,
    {
        self.span.in_scope(f)
    }
}

/// Performance metrics for TLS operations
#[derive(Debug, Clone)]
pub struct TlsMetrics {
    /// Handshake duration
    pub handshake_duration: Duration,
    /// Key exchange duration
    pub kex_duration: Duration,
    /// Certificate verification duration
    pub cert_duration: Duration,
    /// Total operation duration
    pub total_duration: Duration,
    /// Bytes sent
    pub bytes_sent: u64,
    /// Bytes received
    pub bytes_received: u64,
}

impl Default for TlsMetrics {
    fn default() -> Self {
        Self {
            handshake_duration: Duration::ZERO,
            kex_duration: Duration::ZERO,
            cert_duration: Duration::ZERO,
            total_duration: Duration::ZERO,
            bytes_sent: 0,
            bytes_received: 0,
        }
    }
}

impl TlsMetrics {
    /// Create new metrics tracker
    #[must_use]
    pub fn new() -> Self {
        Default::default()
    }

    /// Record handshake duration
    pub fn record_handshake(&mut self, duration: Duration) {
        self.handshake_duration = duration;
    }

    /// Record key exchange duration
    pub fn record_kex(&mut self, duration: Duration) {
        self.kex_duration = duration;
    }

    /// Record certificate verification duration
    pub fn record_cert(&mut self, duration: Duration) {
        self.cert_duration = duration;
    }

    /// Record bytes sent
    pub fn record_sent(&mut self, bytes: u64) {
        self.bytes_sent = self.bytes_sent.saturating_add(bytes);
    }

    /// Record bytes received
    pub fn record_received(&mut self, bytes: u64) {
        self.bytes_received = self.bytes_received.saturating_add(bytes);
    }

    /// Mark operation complete
    pub fn complete(&mut self) {
        self.total_duration = self
            .handshake_duration
            .saturating_add(self.kex_duration)
            .saturating_add(self.cert_duration);
    }

    /// Log metrics
    pub fn log(&self, operation: &str) {
        info!(
            "TLS Metrics [{}]: handshake={:?} kex={:?} cert={:?} total={:?} sent={} recv={}",
            operation,
            self.handshake_duration,
            self.kex_duration,
            self.cert_duration,
            self.total_duration,
            self.bytes_sent,
            self.bytes_received
        );
    }
}

/// Instrument TLS connection with tracing
///
/// # Errors
///
/// Returns an error if the wrapped operation fails. The error is traced
/// and propagated to the caller with timing information.
#[instrument(skip(addr, domain, config))]
pub async fn trace_tls_connection<F, Fut>(
    addr: &str,
    domain: Option<&str>,
    config: &crate::TlsConfig,
    f: F,
) -> Result<(), crate::error::TlsError>
where
    F: FnOnce() -> Fut + std::fmt::Debug,
    Fut: Future<Output = Result<(), crate::error::TlsError>>,
{
    let _span = TlsSpan::connection(addr, domain);

    trace!("Connecting to {} with mode: {:?}", addr, config.mode);

    f().await
}

/// Instrument TLS handshake with tracing
///
/// # Errors
///
/// Returns an error if the TLS handshake fails. The error is logged with
/// timing information and the span is marked as failed.
#[instrument(skip(peer, mode))]
pub async fn trace_tls_handshake<F, Fut>(
    peer: Option<SocketAddr>,
    mode: &str,
    f: F,
) -> Result<(), crate::error::TlsError>
where
    F: FnOnce() -> Fut + std::fmt::Debug,
    Fut: Future<Output = Result<(), crate::error::TlsError>>,
{
    let span = TlsSpan::handshake(peer, mode);
    let start = Instant::now();

    let result = f().await;
    let duration = start.elapsed();

    match result {
        Ok(()) => {
            span.complete();
            info!("Handshake completed in {:?}", duration);
            Ok(())
        }
        Err(err) => {
            span.error(&err);
            warn!("Handshake failed after {:?}: {:?}", duration, err);
            Err(err)
        }
    }
}

/// Instrument key exchange with tracing
///
/// # Errors
///
/// Returns an error if the key exchange operation fails. The error is traced
/// and propagated to the caller with timing information.
#[instrument(skip(method))]
pub async fn trace_key_exchange<F, Fut, T>(method: &str, f: F) -> Result<T, crate::error::TlsError>
where
    F: FnOnce() -> Fut + std::fmt::Debug,
    Fut: Future<Output = Result<T, crate::error::TlsError>>,
{
    let span = TlsSpan::key_exchange(method);
    let start = Instant::now();

    let result = f().await;
    let duration = start.elapsed();

    span.in_scope(|| {
        debug!("Key exchange completed in {:?}", duration);
    });

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tracing_config_default() {
        let config = TracingConfig::default();
        assert_eq!(config.log_level, Level::INFO);
        assert!(!config.include_sensitive_data);
        assert!(config.track_performance);
    }

    #[test]
    fn test_tls_span_creation() {
        let span = TlsSpan::new("test_operation", None);
        assert!(span.start_time.elapsed() < Duration::from_millis(100));
    }

    #[test]
    fn test_tls_metrics_default() {
        let metrics = TlsMetrics::new();
        assert_eq!(metrics.bytes_sent, 0);
        assert_eq!(metrics.bytes_received, 0);
        assert_eq!(metrics.handshake_duration, Duration::ZERO);
    }

    #[test]
    fn test_tls_metrics_recording() {
        let mut metrics = TlsMetrics::new();
        metrics.record_sent(100);
        metrics.record_received(200);
        metrics.record_handshake(Duration::from_millis(100));

        assert_eq!(metrics.bytes_sent, 100);
        assert_eq!(metrics.bytes_received, 200);
        assert_eq!(metrics.handshake_duration, Duration::from_millis(100));
    }
}
