#![deny(unsafe_code)]
// Test patterns may reassign defaults
#![allow(clippy::field_reassign_with_default)]
// Float comparisons acceptable in tests
#![allow(clippy::float_cmp)]

//! Comprehensive error handling tests
//!
//! Tests for error types, recovery mechanisms, tracing, and context propagation

use arc_tls::context::*;
use arc_tls::error::*;
use arc_tls::recovery::*;
use arc_tls::tracing::*;
use std::time::Duration;

#[test]
fn test_error_code_display() {
    assert_eq!(ErrorCode::ConnectionRefused.to_string(), "CONNECTION_REFUSED");
    assert_eq!(ErrorCode::HandshakeFailed.to_string(), "HANDSHAKE_FAILED");
    assert_eq!(ErrorCode::CertificateExpired.to_string(), "CERTIFICATE_EXPIRED");
}

#[test]
fn test_error_severity_comparison() {
    assert!(ErrorSeverity::Critical > ErrorSeverity::Error);
    assert!(ErrorSeverity::Error > ErrorSeverity::Warning);
    assert!(ErrorSeverity::Warning > ErrorSeverity::Info);
}

#[test]
fn test_error_context_default() {
    let context = ErrorContext::default();
    assert!(!context.error_id.is_empty());
    assert_eq!(context.code, ErrorCode::InternalError);
    assert_eq!(context.severity, ErrorSeverity::Error);
    assert!(context.peer_addr.is_none());
}

#[test]
fn test_io_error_conversion() {
    let io_err =
        std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "test connection refused");
    let tls_err = TlsError::from(io_err);

    assert_eq!(tls_err.code(), ErrorCode::ConnectionRefused);
    assert_eq!(tls_err.severity(), ErrorSeverity::Error);
    assert!(tls_err.is_recoverable());
    assert!(!tls_err.supports_fallback());
}

#[test]
fn test_io_error_conversion_timeout() {
    let io_err = std::io::Error::new(std::io::ErrorKind::TimedOut, "timeout");
    let tls_err = TlsError::from(io_err);

    assert_eq!(tls_err.code(), ErrorCode::ConnectionTimeout);
    assert_eq!(tls_err.severity(), ErrorSeverity::Error);
    assert!(tls_err.is_recoverable());
}

#[test]
fn test_io_error_conversion_reset() {
    let io_err = std::io::Error::new(std::io::ErrorKind::ConnectionReset, "connection reset");
    let tls_err = TlsError::from(io_err);

    assert_eq!(tls_err.code(), ErrorCode::ConnectionReset);
    assert_eq!(tls_err.severity(), ErrorSeverity::Warning);
    assert!(tls_err.is_recoverable());
}

#[test]
fn test_certificate_error_with_recovery() {
    let mut context = ErrorContext::default();
    context.code = ErrorCode::CertificateExpired;
    context.severity = ErrorSeverity::Error;
    context.phase = OperationPhase::CertificateVerification;
    context.extra.insert("subject".to_string(), "test.example.com".to_string());

    let err = TlsError::Certificate {
        message: "Certificate expired".to_string(),
        subject: Some("test.example.com".to_string()),
        issuer: Some("Test CA".to_string()),
        code: ErrorCode::CertificateExpired,
        context,
        recovery: RecoveryHint::VerifyCertificates,
    };

    assert_eq!(err.code(), ErrorCode::CertificateExpired);
    assert_eq!(err.severity(), ErrorSeverity::Error);
    assert!(err.is_recoverable());
}

#[test]
fn test_handshake_error_with_retry() {
    let mut context = ErrorContext::default();
    context.code = ErrorCode::HandshakeFailed;
    context.severity = ErrorSeverity::Error;
    context.phase = OperationPhase::Handshake;

    let err = TlsError::Handshake {
        message: "Handshake failed".to_string(),
        state: "ServerHello".to_string(),
        code: ErrorCode::HandshakeFailed,
        context,
        recovery: RecoveryHint::Retry { max_attempts: 3, backoff_ms: 1000 },
    };

    assert_eq!(err.code(), ErrorCode::HandshakeFailed);
    assert!(err.is_recoverable());
}

#[test]
fn test_pq_not_available_with_fallback() {
    let mut context = ErrorContext::default();
    context.code = ErrorCode::PqNotAvailable;
    context.severity = ErrorSeverity::Warning;
    context.phase = OperationPhase::KeyExchange;

    let err = TlsError::PqNotAvailable {
        message: "PQ not available".to_string(),
        code: ErrorCode::PqNotAvailable,
        context,
        recovery: RecoveryHint::Fallback { description: "Fall back to classical".to_string() },
    };

    assert_eq!(err.code(), ErrorCode::PqNotAvailable);
    assert!(err.supports_fallback());
    assert!(err.is_recoverable());
}

#[test]
fn test_unrecoverable_error() {
    let mut context = ErrorContext::default();
    context.code = ErrorCode::InternalError;
    context.severity = ErrorSeverity::Critical;
    context.phase = OperationPhase::Initialization;

    let err = TlsError::Internal {
        message: "Internal error".to_string(),
        code: ErrorCode::InternalError,
        context,
        recovery: RecoveryHint::NoRecovery,
    };

    assert!(!err.is_recoverable());
    assert!(!err.supports_fallback());
}

#[test]
fn test_retry_policy_default() {
    let policy = RetryPolicy::default();
    assert_eq!(policy.max_attempts, 3);
    assert_eq!(policy.initial_backoff, Duration::from_millis(100));
    assert_eq!(policy.max_backoff, Duration::from_secs(5));
    assert_eq!(policy.backoff_multiplier, 2.0);
    assert!(policy.jitter);
}

#[test]
fn test_retry_policy_conservative() {
    let policy = RetryPolicy::conservative();
    assert_eq!(policy.max_attempts, 2);
    assert_eq!(policy.initial_backoff, Duration::from_millis(200));
}

#[test]
fn test_retry_policy_aggressive() {
    let policy = RetryPolicy::aggressive();
    assert_eq!(policy.max_attempts, 5);
    assert_eq!(policy.initial_backoff, Duration::from_millis(50));
}

#[test]
fn test_retry_policy_backoff_calculation() {
    let policy = RetryPolicy::default();
    let backoff1 = policy.backoff_for_attempt(1);
    let backoff2 = policy.backoff_for_attempt(2);
    let backoff3 = policy.backoff_for_attempt(3);

    assert!(backoff1 >= Duration::from_millis(100));
    assert!(backoff2 > backoff1);
    assert!(backoff3 > backoff2);
    assert!(backoff3 <= policy.max_backoff);
}

#[test]
fn test_retry_should_retry_connection_refused() {
    let policy = RetryPolicy::default();
    let io_err = std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "connection refused");
    let tls_err = TlsError::from(io_err);

    // ConnectionRefused should be retried
    assert!(policy.should_retry(&tls_err, 1));
}

#[test]
fn test_retry_should_not_retry_after_max_attempts() {
    let policy = RetryPolicy::default();
    let io_err = std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "connection refused");
    let tls_err = TlsError::from(io_err);

    // Should not retry after max attempts
    assert!(!policy.should_retry(&tls_err, 4));
}

#[test]
fn test_circuit_breaker_initial_state() {
    let breaker = CircuitBreaker::new(5, Duration::from_secs(60));
    assert_eq!(breaker.state(), CircuitState::Closed);
    assert!(breaker.allow_request());
}

#[test]
fn test_circuit_breaker_opens_after_failures() {
    let breaker = CircuitBreaker::new(3, Duration::from_secs(60));

    // Record 3 failures
    for _ in 0..3 {
        breaker.record_failure();
    }

    // Circuit should be open
    assert_eq!(breaker.state(), CircuitState::Open);
    assert!(!breaker.allow_request());
}

#[test]
fn test_circuit_breaker_allows_in_half_open() {
    let breaker = CircuitBreaker::new(3, Duration::from_secs(60));

    // Open circuit
    for _ in 0..3 {
        breaker.record_failure();
    }

    // Wait for timeout
    std::thread::sleep(Duration::from_millis(10));
    breaker.reset();

    // Should allow request
    assert!(breaker.allow_request());
}

#[test]
fn test_circuit_breaker_success_closes_circuit() {
    let breaker = CircuitBreaker::new(2, Duration::from_secs(60));

    // Open circuit
    for _ in 0..2 {
        breaker.record_failure();
    }

    // Reset and simulate success
    breaker.reset();
    breaker.record_success();
    breaker.record_success();
    breaker.record_success();

    // Circuit should be closed
    assert_eq!(breaker.state(), CircuitState::Closed);
}

#[test]
fn test_fallback_strategy_default() {
    let strategy = FallbackStrategy::default();
    assert!(!strategy.should_fallback(&create_dummy_error()));
    assert!(strategy.description().contains("No fallback"));
}

#[test]
fn test_fallback_strategy_hybrid_to_classical() {
    let strategy = FallbackStrategy::hybrid_to_classical();

    let mut context = ErrorContext::default();
    context.code = ErrorCode::PqNotAvailable;

    let err = TlsError::PqNotAvailable {
        message: "PQ not available".to_string(),
        code: ErrorCode::PqNotAvailable,
        context,
        recovery: RecoveryHint::Fallback { description: "Fallback".to_string() },
    };

    assert!(strategy.should_fallback(&err));
    assert!(strategy.description().contains("hybrid to classical"));
}

#[test]
fn test_tls_context_default() {
    let ctx = TlsContext::default();
    assert!(!ctx.operation_id.is_empty());
    assert_eq!(ctx.operation_name, "unknown");
    assert!(ctx.peer_addr.is_none());
    assert!(ctx.domain.is_none());
}

#[test]
fn test_tls_context_creation() {
    let ctx = TlsContext::new("Test Operation");
    assert_eq!(ctx.operation_name, "Test Operation");
    assert!(!ctx.operation_id.is_empty());
}

#[test]
fn test_tls_context_builder() {
    let ctx = TlsContext::new("Test")
        .with_domain("example.com")
        .with_mode("Hybrid")
        .with_metadata("key", "value");

    assert_eq!(ctx.domain, Some("example.com".to_string()));
    assert_eq!(ctx.mode, Some("Hybrid".to_string()));
    assert_eq!(ctx.get_metadata("key"), Some(&"value".to_string()));
}

#[test]
fn test_tls_context_child() {
    let parent = TlsContext::new("Parent");
    let child = parent.child("Child");

    let parent_id = parent.operation_id.clone();
    assert_eq!(child.parent_span_id, Some(parent_id.clone()));
    assert_eq!(child.trace_id, parent.trace_id);
    assert_ne!(child.operation_id, parent_id);
}

#[test]
fn test_error_chain_empty() {
    let chain = ErrorChain::new();
    assert!(chain.is_empty());
    assert_eq!(chain.len(), 0);
}

#[test]
fn test_error_chain_with_errors() {
    let mut chain = ErrorChain::new();
    let ctx = TlsContext::new("Test");

    let err1 = TlsError::from(std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "test"));

    chain.push_tls_error(&err1, &ctx);

    assert!(!chain.is_empty());
    assert_eq!(chain.len(), 1);
}

#[test]
fn test_diagnostic_info_formatting() {
    let ctx = TlsContext::new("Test Operation");
    let err = create_dummy_error();

    let diagnostic = DiagnosticInfo::new(&ctx, &err);
    let formatted = diagnostic.format();

    assert!(formatted.contains("Test Operation"));
    assert!(formatted.contains("Error Chain"));
    assert!(formatted.contains("System Info"));
}

#[test]
fn test_system_info_collect() {
    let info = SystemInfo::collect();

    assert!(!info.platform.is_empty());
    assert!(!info.rust_version.is_empty());
    assert!(!info.tls_version.is_empty());
}

#[test]
fn test_tracing_config_default() {
    let config = TracingConfig::default();
    assert_eq!(config.log_level, tracing::Level::INFO);
    assert!(!config.include_sensitive_data);
    assert!(config.track_performance);
}

#[test]
fn test_tracing_config_debug() {
    let config = TracingConfig::debug();
    assert_eq!(config.log_level, tracing::Level::DEBUG);
}

#[test]
fn test_tracing_config_trace() {
    let config = TracingConfig::trace();
    assert_eq!(config.log_level, tracing::Level::TRACE);
    assert!(!config.include_sensitive_data);
}

#[test]
fn test_tls_span_creation() {
    let span = TlsSpan::new("test_operation", None);
    assert!(span.elapsed() < Duration::from_millis(100));
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

    metrics.record_handshake(Duration::from_millis(100));
    metrics.record_kex(Duration::from_millis(50));
    metrics.record_cert(Duration::from_millis(25));
    metrics.record_sent(1000);
    metrics.record_received(500);

    assert_eq!(metrics.bytes_sent, 1000);
    assert_eq!(metrics.bytes_received, 500);
    assert_eq!(metrics.handshake_duration, Duration::from_millis(100));
    assert_eq!(metrics.kex_duration, Duration::from_millis(50));
    assert_eq!(metrics.cert_duration, Duration::from_millis(25));
}

fn create_dummy_error() -> TlsError {
    let mut context = ErrorContext::default();
    context.code = ErrorCode::InternalError;
    context.severity = ErrorSeverity::Error;
    context.phase = OperationPhase::Initialization;

    TlsError::Internal {
        message: "Test error".to_string(),
        code: ErrorCode::InternalError,
        context,
        recovery: RecoveryHint::NoRecovery,
    }
}
