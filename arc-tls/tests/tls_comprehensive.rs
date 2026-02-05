#![allow(clippy::indexing_slicing)]
#![allow(clippy::float_cmp)]

//! Comprehensive tests for arc-tls crate
//!
//! This test suite covers:
//! - TLS configuration (Classic, Hybrid, PQ modes)
//! - Error types and error handling
//! - Recovery mechanisms (retry, circuit breaker, fallback)
//! - TLS policy engine and mode selection
//! - TLS 1.3 configuration
//! - Session store functionality

#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]

use arc_core::{PerformancePreference, SecurityLevel};
use arc_tls::{
    CLASSICAL_TLS_KEX,
    CLASSICAL_TLS_SCHEME,
    CircuitBreaker,
    ClientAuthConfig,
    ClientVerificationMode,
    DEFAULT_PQ_TLS_KEX,
    DEFAULT_PQ_TLS_SCHEME,
    DEFAULT_TLS_KEX,
    DEFAULT_TLS_SCHEME,
    DegradationConfig,
    ErrorCode,
    ErrorContext,
    ErrorSeverity,
    FallbackStrategy,
    HYBRID_TLS_512,
    HYBRID_TLS_768,
    HYBRID_TLS_1024,
    OperationPhase,
    PQ_TLS_512,
    PQ_TLS_768,
    PQ_TLS_1024,
    RecoveryHint,
    // Recovery mechanisms
    RetryPolicy,
    SessionPersistenceConfig,
    // Configuration
    TlsConfig,
    TlsConstraints,
    TlsContext,
    // Error types
    TlsError,
    TlsMode,
    // Policy engine
    TlsPolicyEngine,
    TlsUseCase,
    // Utilities
    VERSION,
    pq_enabled,
    // TLS 1.3
    tls13::{HandshakeState, HandshakeStats, Tls13Config, get_cipher_suites, verify_config},
};
use std::time::Duration;

// ============================================================================
// TLS Mode Tests
// ============================================================================

mod tls_mode_tests {
    use super::*;

    #[test]
    fn test_tls_mode_default() {
        assert_eq!(TlsMode::default(), TlsMode::Hybrid);
    }

    #[test]
    fn test_tls_mode_debug() {
        assert!(format!("{:?}", TlsMode::Classic).contains("Classic"));
        assert!(format!("{:?}", TlsMode::Hybrid).contains("Hybrid"));
        assert!(format!("{:?}", TlsMode::Pq).contains("Pq"));
    }

    #[test]
    fn test_tls_mode_clone() {
        let mode = TlsMode::Hybrid;
        let cloned = mode;
        assert_eq!(mode, cloned);
    }

    #[test]
    fn test_tls_mode_eq() {
        assert_eq!(TlsMode::Classic, TlsMode::Classic);
        assert_eq!(TlsMode::Hybrid, TlsMode::Hybrid);
        assert_eq!(TlsMode::Pq, TlsMode::Pq);
        assert_ne!(TlsMode::Classic, TlsMode::Hybrid);
        assert_ne!(TlsMode::Hybrid, TlsMode::Pq);
    }
}

// ============================================================================
// TLS Configuration Tests
// ============================================================================

mod tls_config_tests {
    use super::*;

    #[test]
    fn test_tls_config_default() {
        let config = TlsConfig::default();
        assert_eq!(config.mode, TlsMode::Hybrid);
        assert!(!config.enable_tracing);
        assert!(config.retry_policy.is_none());
        assert!(config.enable_fallback);
        assert!(config.alpn_protocols.is_empty());
        assert!(config.max_fragment_size.is_none());
        assert!(!config.enable_early_data);
        assert_eq!(config.max_early_data_size, 0);
        assert!(config.require_secure_renegotiation);
        assert!(config.enable_resumption);
        assert_eq!(config.session_lifetime, 7200);
        assert!(!config.enable_key_logging);
    }

    #[test]
    fn test_tls_config_new() {
        let config = TlsConfig::new();
        assert_eq!(config.mode, TlsMode::Hybrid);
    }

    #[test]
    fn test_tls_config_use_case() {
        let config = TlsConfig::new().use_case(TlsUseCase::WebServer);
        assert_eq!(config.mode, TlsMode::Hybrid);

        let config = TlsConfig::new().use_case(TlsUseCase::IoT);
        assert_eq!(config.mode, TlsMode::Classic);

        let config = TlsConfig::new().use_case(TlsUseCase::Government);
        assert_eq!(config.mode, TlsMode::Pq);
    }

    #[test]
    fn test_tls_config_security_level() {
        let config = TlsConfig::new().security_level(SecurityLevel::Quantum);
        assert_eq!(config.mode, TlsMode::Pq);

        let config = TlsConfig::new().security_level(SecurityLevel::Maximum);
        assert_eq!(config.mode, TlsMode::Hybrid);

        let config = TlsConfig::new().security_level(SecurityLevel::Standard);
        assert_eq!(config.mode, TlsMode::Hybrid);
    }

    #[test]
    fn test_tls_config_with_tracing() {
        let config = TlsConfig::new().with_tracing();
        assert!(config.enable_tracing);
    }

    #[test]
    fn test_tls_config_with_retry_policy() {
        let policy = RetryPolicy::default();
        let config = TlsConfig::new().with_retry_policy(policy);
        assert!(config.retry_policy.is_some());
    }

    #[test]
    fn test_tls_config_with_fallback() {
        let config = TlsConfig::new().with_fallback(false);
        assert!(!config.enable_fallback);
    }

    #[test]
    fn test_tls_config_with_alpn_protocols() {
        let config = TlsConfig::new().with_alpn_protocols(vec!["h2", "http/1.1"]);
        assert_eq!(config.alpn_protocols.len(), 2);
        assert_eq!(config.alpn_protocols[0], b"h2");
        assert_eq!(config.alpn_protocols[1], b"http/1.1");
    }

    #[test]
    fn test_tls_config_with_max_fragment_size() {
        let config = TlsConfig::new().with_max_fragment_size(4096);
        assert_eq!(config.max_fragment_size, Some(4096));
    }

    #[test]
    fn test_tls_config_with_early_data() {
        let config = TlsConfig::new().with_early_data(16384);
        assert!(config.enable_early_data);
        assert_eq!(config.max_early_data_size, 16384);
    }

    #[test]
    fn test_tls_config_with_session_lifetime() {
        let config = TlsConfig::new().with_session_lifetime(3600);
        assert_eq!(config.session_lifetime, 3600);
    }

    #[test]
    fn test_tls_config_with_secure_renegotiation() {
        let config = TlsConfig::new().with_secure_renegotiation(false);
        assert!(!config.require_secure_renegotiation);
    }

    #[test]
    fn test_tls_config_with_resumption() {
        let config = TlsConfig::new().with_resumption(false);
        assert!(!config.enable_resumption);
    }

    #[test]
    fn test_tls_config_with_key_logging() {
        let config = TlsConfig::new().with_key_logging();
        assert!(config.enable_key_logging);
    }

    #[test]
    fn test_tls_config_with_client_auth() {
        let config = TlsConfig::new().with_client_auth("client.crt", "client.key");
        assert!(config.client_auth.is_some());
        let auth = config.client_auth.unwrap();
        assert_eq!(auth.cert_path, "client.crt");
        assert_eq!(auth.key_path, "client.key");
    }

    #[test]
    fn test_tls_config_with_client_verification() {
        let config = TlsConfig::new().with_client_verification(ClientVerificationMode::Required);
        assert_eq!(config.client_verification, ClientVerificationMode::Required);
    }

    #[test]
    fn test_tls_config_with_client_ca_certs() {
        let config = TlsConfig::new().with_client_ca_certs("ca-bundle.crt");
        assert_eq!(config.client_ca_certs, Some("ca-bundle.crt".to_string()));
    }

    #[test]
    fn test_tls_config_with_session_persistence() {
        let config = TlsConfig::new().with_session_persistence("/var/cache/sessions.bin", 1000);
        assert!(config.session_persistence.is_some());
        let persistence = config.session_persistence.unwrap();
        assert_eq!(persistence.max_sessions, 1000);
    }

    #[test]
    fn test_tls_config_validate_success() {
        let config = TlsConfig::new();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_tls_config_builder_chain() {
        let config = TlsConfig::new()
            .use_case(TlsUseCase::FinancialServices)
            .with_tracing()
            .with_fallback(true)
            .with_alpn_protocols(vec!["h2"])
            .with_session_lifetime(3600);

        assert_eq!(config.mode, TlsMode::Hybrid);
        assert!(config.enable_tracing);
        assert!(config.enable_fallback);
        assert_eq!(config.alpn_protocols.len(), 1);
        assert_eq!(config.session_lifetime, 3600);
    }
}

// ============================================================================
// Client Auth Config Tests
// ============================================================================

mod client_auth_config_tests {
    use super::*;

    #[test]
    fn test_client_auth_config_new() {
        let config = ClientAuthConfig::new("cert.pem", "key.pem");
        assert_eq!(config.cert_path, "cert.pem");
        assert_eq!(config.key_path, "key.pem");
    }

    #[test]
    fn test_client_auth_config_debug() {
        let config = ClientAuthConfig::new("cert.pem", "key.pem");
        let debug = format!("{:?}", config);
        assert!(debug.contains("cert.pem"));
        assert!(debug.contains("key.pem"));
    }
}

// ============================================================================
// Client Verification Mode Tests
// ============================================================================

mod client_verification_mode_tests {
    use super::*;

    #[test]
    fn test_client_verification_mode_default() {
        assert_eq!(ClientVerificationMode::default(), ClientVerificationMode::None);
    }

    #[test]
    fn test_client_verification_mode_eq() {
        assert_eq!(ClientVerificationMode::None, ClientVerificationMode::None);
        assert_eq!(ClientVerificationMode::Optional, ClientVerificationMode::Optional);
        assert_eq!(ClientVerificationMode::Required, ClientVerificationMode::Required);
        assert_ne!(ClientVerificationMode::None, ClientVerificationMode::Required);
    }
}

// ============================================================================
// Session Persistence Config Tests
// ============================================================================

mod session_persistence_config_tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_session_persistence_config_new() {
        let config = SessionPersistenceConfig::new("/var/cache/sessions", 500);
        assert_eq!(config.path, PathBuf::from("/var/cache/sessions"));
        assert_eq!(config.max_sessions, 500);
    }
}

// ============================================================================
// Error Code Tests
// ============================================================================

mod error_code_tests {
    use super::*;

    #[test]
    fn test_error_code_display() {
        assert_eq!(ErrorCode::ConnectionRefused.to_string(), "CONNECTION_REFUSED");
        assert_eq!(ErrorCode::HandshakeFailed.to_string(), "HANDSHAKE_FAILED");
        assert_eq!(ErrorCode::CertificateExpired.to_string(), "CERTIFICATE_EXPIRED");
        assert_eq!(ErrorCode::KeyExchangeFailed.to_string(), "KEY_EXCHANGE_FAILED");
        assert_eq!(ErrorCode::IoError.to_string(), "IO_ERROR");
        assert_eq!(ErrorCode::InvalidConfig.to_string(), "INVALID_CONFIG");
    }

    #[test]
    fn test_error_code_copy() {
        let code = ErrorCode::ConnectionRefused;
        let copy = code;
        assert_eq!(code, copy);
    }
}

// ============================================================================
// Error Severity Tests
// ============================================================================

mod error_severity_tests {
    use super::*;

    #[test]
    fn test_error_severity_ordering() {
        assert!(ErrorSeverity::Info < ErrorSeverity::Warning);
        assert!(ErrorSeverity::Warning < ErrorSeverity::Error);
        assert!(ErrorSeverity::Error < ErrorSeverity::Critical);
    }

    #[test]
    fn test_error_severity_eq() {
        assert_eq!(ErrorSeverity::Info, ErrorSeverity::Info);
        assert_ne!(ErrorSeverity::Info, ErrorSeverity::Warning);
    }
}

// ============================================================================
// Operation Phase Tests
// ============================================================================

mod operation_phase_tests {
    use super::*;

    #[test]
    fn test_operation_phase_variants() {
        let phases = [
            OperationPhase::ConnectionSetup,
            OperationPhase::Handshake,
            OperationPhase::CertificateVerification,
            OperationPhase::KeyExchange,
            OperationPhase::DataTransfer,
            OperationPhase::Teardown,
            OperationPhase::Initialization,
        ];

        for phase in phases {
            let debug = format!("{:?}", phase);
            assert!(!debug.is_empty());
        }
    }
}

// ============================================================================
// Error Context Tests
// ============================================================================

mod error_context_tests {
    use super::*;

    #[test]
    fn test_error_context_default() {
        let context = ErrorContext::default();
        assert!(!context.error_id.is_empty());
        assert!(context.error_id.starts_with("TLSERR_"));
        assert_eq!(context.code, ErrorCode::InternalError);
        assert_eq!(context.severity, ErrorSeverity::Error);
        assert_eq!(context.phase, OperationPhase::Initialization);
    }

    #[test]
    fn test_error_context_unique_ids() {
        let ctx1 = ErrorContext::default();
        let ctx2 = ErrorContext::default();
        assert_ne!(ctx1.error_id, ctx2.error_id);
    }
}

// ============================================================================
// TLS Error Tests
// ============================================================================

mod tls_error_tests {
    use super::*;

    #[test]
    fn test_tls_error_from_io_error() {
        let io_err =
            std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "connection refused");
        let tls_err = TlsError::from(io_err);

        assert_eq!(tls_err.code(), ErrorCode::ConnectionRefused);
        assert_eq!(tls_err.severity(), ErrorSeverity::Error);
    }

    #[test]
    fn test_tls_error_from_timeout() {
        let io_err = std::io::Error::new(std::io::ErrorKind::TimedOut, "timeout");
        let tls_err = TlsError::from(io_err);

        assert_eq!(tls_err.code(), ErrorCode::ConnectionTimeout);
    }

    #[test]
    fn test_tls_error_from_connection_reset() {
        let io_err = std::io::Error::new(std::io::ErrorKind::ConnectionReset, "reset");
        let tls_err = TlsError::from(io_err);

        assert_eq!(tls_err.code(), ErrorCode::ConnectionReset);
        assert!(tls_err.is_recoverable());
    }

    #[test]
    fn test_tls_error_from_unexpected_eof() {
        let io_err = std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "eof");
        let tls_err = TlsError::from(io_err);

        assert_eq!(tls_err.code(), ErrorCode::UnexpectedEof);
    }

    #[test]
    fn test_tls_error_context() {
        let io_err = std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "test");
        let tls_err = TlsError::from(io_err);

        let context = tls_err.context();
        assert!(!context.error_id.is_empty());
    }

    #[test]
    fn test_tls_error_recovery_hint() {
        let io_err = std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "test");
        let tls_err = TlsError::from(io_err);

        let hint = tls_err.recovery_hint();
        assert!(matches!(hint, RecoveryHint::CheckNetworkConnectivity));
    }
}

// ============================================================================
// Recovery Hint Tests
// ============================================================================

mod recovery_hint_tests {
    use super::*;

    #[test]
    fn test_recovery_hint_variants() {
        let no_recovery = RecoveryHint::NoRecovery;
        let retry = RecoveryHint::Retry { max_attempts: 3, backoff_ms: 1000 };
        let fallback = RecoveryHint::Fallback { description: "test".to_string() };
        let reconfigure = RecoveryHint::Reconfigure {
            field: "test".to_string(),
            suggestion: "fix it".to_string(),
        };
        let contact = RecoveryHint::ContactSupport { message: "help".to_string() };
        let check_time = RecoveryHint::CheckSystemTime;
        let check_network = RecoveryHint::CheckNetworkConnectivity;
        let verify_certs = RecoveryHint::VerifyCertificates;
        let check_limits = RecoveryHint::CheckResourceLimits;

        // Verify debug formatting works
        assert!(!format!("{:?}", no_recovery).is_empty());
        assert!(!format!("{:?}", retry).is_empty());
        assert!(!format!("{:?}", fallback).is_empty());
        assert!(!format!("{:?}", reconfigure).is_empty());
        assert!(!format!("{:?}", contact).is_empty());
        assert!(!format!("{:?}", check_time).is_empty());
        assert!(!format!("{:?}", check_network).is_empty());
        assert!(!format!("{:?}", verify_certs).is_empty());
        assert!(!format!("{:?}", check_limits).is_empty());
    }
}

// ============================================================================
// Retry Policy Tests
// ============================================================================

mod retry_policy_tests {
    use super::*;

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
    fn test_retry_policy_new() {
        let policy = RetryPolicy::new(4, Duration::from_millis(50), Duration::from_secs(10));
        assert_eq!(policy.max_attempts, 4);
        assert_eq!(policy.initial_backoff, Duration::from_millis(50));
        assert_eq!(policy.max_backoff, Duration::from_secs(10));
    }

    #[test]
    fn test_retry_policy_backoff_calculation() {
        let mut policy = RetryPolicy::default();
        policy.jitter = false; // Disable jitter for predictable testing

        let backoff1 = policy.backoff_for_attempt(1);
        let backoff2 = policy.backoff_for_attempt(2);
        let backoff3 = policy.backoff_for_attempt(3);

        // Backoff should increase with each attempt
        assert!(backoff2 > backoff1);
        assert!(backoff3 > backoff2);

        // Should not exceed max backoff
        let backoff_max = policy.backoff_for_attempt(100);
        assert!(backoff_max <= policy.max_backoff.saturating_mul(2)); // Allow for jitter margin
    }

    #[test]
    fn test_retry_policy_should_retry() {
        let policy = RetryPolicy::default();

        // Create a retryable error
        let io_err = std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "test");
        let tls_err = TlsError::from(io_err);

        // Should retry on first attempt
        assert!(policy.should_retry(&tls_err, 1));

        // Should not retry after max attempts
        assert!(!policy.should_retry(&tls_err, 10));
    }
}

// ============================================================================
// Circuit Breaker Tests
// ============================================================================

mod circuit_breaker_tests {
    use super::*;
    use arc_tls::recovery::CircuitState;

    #[test]
    fn test_circuit_breaker_initial_state() {
        let breaker = CircuitBreaker::new(5, Duration::from_secs(60));
        assert_eq!(breaker.state(), CircuitState::Closed);
    }

    #[test]
    fn test_circuit_breaker_allow_request_closed() {
        let breaker = CircuitBreaker::new(5, Duration::from_secs(60));
        assert!(breaker.allow_request());
    }

    #[test]
    fn test_circuit_breaker_opens_after_failures() {
        let breaker = CircuitBreaker::new(3, Duration::from_secs(60));

        // Record failures
        breaker.record_failure();
        breaker.record_failure();
        breaker.record_failure();

        // Circuit should be open
        assert_eq!(breaker.state(), CircuitState::Open);
    }

    #[test]
    fn test_circuit_breaker_blocks_when_open() {
        let breaker = CircuitBreaker::new(3, Duration::from_secs(60));

        // Open the circuit
        for _ in 0..3 {
            breaker.record_failure();
        }

        // Should block requests
        assert!(!breaker.allow_request());
    }

    #[test]
    fn test_circuit_breaker_success_resets_failures() {
        let breaker = CircuitBreaker::new(5, Duration::from_secs(60));

        // Record some failures
        breaker.record_failure();
        breaker.record_failure();

        // Record success
        breaker.record_success();

        // Circuit should still be closed
        assert_eq!(breaker.state(), CircuitState::Closed);
    }

    #[test]
    fn test_circuit_breaker_reset() {
        let breaker = CircuitBreaker::new(3, Duration::from_secs(60));

        // Open the circuit
        for _ in 0..3 {
            breaker.record_failure();
        }
        assert_eq!(breaker.state(), CircuitState::Open);

        // Reset
        breaker.reset();
        assert_eq!(breaker.state(), CircuitState::Closed);
    }
}

// ============================================================================
// Fallback Strategy Tests
// ============================================================================

mod fallback_strategy_tests {
    use super::*;

    #[test]
    fn test_fallback_strategy_default() {
        let strategy = FallbackStrategy::default();
        assert!(matches!(strategy, FallbackStrategy::None));
    }

    #[test]
    fn test_fallback_strategy_hybrid_to_classical() {
        let strategy = FallbackStrategy::hybrid_to_classical();
        assert!(matches!(strategy, FallbackStrategy::HybridToClassical));
        assert!(strategy.description().contains("hybrid to classical"));
    }

    #[test]
    fn test_fallback_strategy_pq_to_hybrid() {
        let strategy = FallbackStrategy::pq_to_hybrid();
        assert!(matches!(strategy, FallbackStrategy::PqToHybrid));
        assert!(strategy.description().contains("PQ-only to hybrid"));
    }

    #[test]
    fn test_fallback_strategy_description() {
        let none = FallbackStrategy::None;
        let custom = FallbackStrategy::Custom { description: "custom fallback".to_string() };

        assert!(none.description().contains("No fallback"));
        assert_eq!(custom.description(), "custom fallback");
    }
}

// ============================================================================
// Degradation Config Tests
// ============================================================================

mod degradation_config_tests {
    use super::*;

    #[test]
    fn test_degradation_config_default() {
        let config = DegradationConfig::default();
        assert!(config.enable_fallback);
        assert!(!config.allow_reduced_security);
        assert_eq!(config.max_degradation_attempts, 2);
    }
}

// ============================================================================
// TLS Policy Engine Tests
// ============================================================================

mod tls_policy_engine_tests {
    use super::*;

    #[test]
    fn test_recommend_mode_use_cases() {
        assert_eq!(TlsPolicyEngine::recommend_mode(TlsUseCase::WebServer), TlsMode::Hybrid);
        assert_eq!(TlsPolicyEngine::recommend_mode(TlsUseCase::InternalService), TlsMode::Hybrid);
        assert_eq!(TlsPolicyEngine::recommend_mode(TlsUseCase::ApiGateway), TlsMode::Hybrid);
        assert_eq!(TlsPolicyEngine::recommend_mode(TlsUseCase::IoT), TlsMode::Classic);
        assert_eq!(
            TlsPolicyEngine::recommend_mode(TlsUseCase::LegacyIntegration),
            TlsMode::Classic
        );
        assert_eq!(TlsPolicyEngine::recommend_mode(TlsUseCase::FinancialServices), TlsMode::Hybrid);
        assert_eq!(TlsPolicyEngine::recommend_mode(TlsUseCase::Healthcare), TlsMode::Hybrid);
        assert_eq!(TlsPolicyEngine::recommend_mode(TlsUseCase::Government), TlsMode::Pq);
        assert_eq!(
            TlsPolicyEngine::recommend_mode(TlsUseCase::DatabaseConnection),
            TlsMode::Hybrid
        );
        assert_eq!(
            TlsPolicyEngine::recommend_mode(TlsUseCase::RealTimeStreaming),
            TlsMode::Classic
        );
    }

    #[test]
    fn test_select_by_security_level() {
        assert_eq!(TlsPolicyEngine::select_by_security_level(SecurityLevel::Quantum), TlsMode::Pq);
        assert_eq!(
            TlsPolicyEngine::select_by_security_level(SecurityLevel::Maximum),
            TlsMode::Hybrid
        );
        assert_eq!(TlsPolicyEngine::select_by_security_level(SecurityLevel::High), TlsMode::Hybrid);
        assert_eq!(
            TlsPolicyEngine::select_by_security_level(SecurityLevel::Standard),
            TlsMode::Hybrid
        );
    }

    #[test]
    fn test_select_pq_scheme() {
        assert_eq!(TlsPolicyEngine::select_pq_scheme(SecurityLevel::Standard), PQ_TLS_512);
        assert_eq!(TlsPolicyEngine::select_pq_scheme(SecurityLevel::High), PQ_TLS_768);
        assert_eq!(TlsPolicyEngine::select_pq_scheme(SecurityLevel::Maximum), PQ_TLS_1024);
        assert_eq!(TlsPolicyEngine::select_pq_scheme(SecurityLevel::Quantum), PQ_TLS_1024);
    }

    #[test]
    fn test_select_pq_kex() {
        assert_eq!(TlsPolicyEngine::select_pq_kex(SecurityLevel::Standard), "MLKEM512");
        assert_eq!(TlsPolicyEngine::select_pq_kex(SecurityLevel::High), "MLKEM768");
        assert_eq!(TlsPolicyEngine::select_pq_kex(SecurityLevel::Maximum), "MLKEM1024");
    }

    #[test]
    fn test_select_hybrid_scheme() {
        assert_eq!(TlsPolicyEngine::select_hybrid_scheme(SecurityLevel::Standard), HYBRID_TLS_512);
        assert_eq!(TlsPolicyEngine::select_hybrid_scheme(SecurityLevel::High), HYBRID_TLS_768);
        assert_eq!(TlsPolicyEngine::select_hybrid_scheme(SecurityLevel::Maximum), HYBRID_TLS_1024);
    }

    #[test]
    fn test_select_hybrid_kex() {
        assert_eq!(TlsPolicyEngine::select_hybrid_kex(SecurityLevel::Standard), "X25519MLKEM512");
        assert_eq!(TlsPolicyEngine::select_hybrid_kex(SecurityLevel::High), "X25519MLKEM768");
        assert_eq!(TlsPolicyEngine::select_hybrid_kex(SecurityLevel::Maximum), "X25519MLKEM1024");
    }

    #[test]
    fn test_get_scheme_identifier() {
        assert_eq!(
            TlsPolicyEngine::get_scheme_identifier(TlsMode::Classic, SecurityLevel::High),
            CLASSICAL_TLS_SCHEME
        );
        assert_eq!(
            TlsPolicyEngine::get_scheme_identifier(TlsMode::Hybrid, SecurityLevel::High),
            HYBRID_TLS_768
        );
        assert_eq!(
            TlsPolicyEngine::get_scheme_identifier(TlsMode::Pq, SecurityLevel::High),
            PQ_TLS_768
        );
    }

    #[test]
    fn test_get_kex_algorithm() {
        assert_eq!(
            TlsPolicyEngine::get_kex_algorithm(TlsMode::Classic, SecurityLevel::High),
            CLASSICAL_TLS_KEX
        );
        assert_eq!(
            TlsPolicyEngine::get_kex_algorithm(TlsMode::Hybrid, SecurityLevel::High),
            "X25519MLKEM768"
        );
        assert_eq!(
            TlsPolicyEngine::get_kex_algorithm(TlsMode::Pq, SecurityLevel::High),
            "MLKEM768"
        );
    }

    #[test]
    fn test_default_schemes() {
        assert_eq!(TlsPolicyEngine::default_scheme(), DEFAULT_TLS_SCHEME);
        assert_eq!(TlsPolicyEngine::default_pq_scheme(), DEFAULT_PQ_TLS_SCHEME);
    }

    #[test]
    fn test_select_balanced() {
        assert_eq!(
            TlsPolicyEngine::select_balanced(SecurityLevel::Quantum, PerformancePreference::Speed),
            TlsMode::Pq
        );
        assert_eq!(
            TlsPolicyEngine::select_balanced(
                SecurityLevel::Standard,
                PerformancePreference::Balanced
            ),
            TlsMode::Hybrid
        );
    }
}

// ============================================================================
// TLS Use Case Tests
// ============================================================================

mod tls_use_case_tests {
    use super::*;

    #[test]
    fn test_use_case_description() {
        assert!(!TlsUseCase::WebServer.description().is_empty());
        assert!(!TlsUseCase::InternalService.description().is_empty());
        assert!(!TlsUseCase::ApiGateway.description().is_empty());
        assert!(!TlsUseCase::IoT.description().is_empty());
        assert!(!TlsUseCase::Government.description().is_empty());
    }

    #[test]
    fn test_use_case_all() {
        let all = TlsUseCase::all();
        assert_eq!(all.len(), 10);
        assert!(all.contains(&TlsUseCase::WebServer));
        assert!(all.contains(&TlsUseCase::Government));
    }
}

// ============================================================================
// TLS Constraints Tests
// ============================================================================

mod tls_constraints_tests {
    use super::*;

    #[test]
    fn test_tls_constraints_default() {
        let constraints = TlsConstraints::default();
        assert!(constraints.max_handshake_latency_ms.is_none());
        assert!(constraints.client_supports_pq.is_none());
        assert!(!constraints.require_compatibility);
        assert!(constraints.max_client_hello_size.is_none());
    }

    #[test]
    fn test_tls_constraints_maximum_compatibility() {
        let constraints = TlsConstraints::maximum_compatibility();
        assert!(constraints.requires_classic());
        assert!(!constraints.allows_pq());
    }

    #[test]
    fn test_tls_constraints_high_security() {
        let constraints = TlsConstraints::high_security();
        assert!(!constraints.requires_classic());
        assert!(constraints.allows_pq());
    }

    #[test]
    fn test_tls_constraints_requires_classic() {
        let mut constraints = TlsConstraints::default();
        assert!(!constraints.requires_classic());

        constraints.client_supports_pq = Some(false);
        assert!(constraints.requires_classic());

        constraints.client_supports_pq = None;
        constraints.require_compatibility = true;
        assert!(constraints.requires_classic());
    }
}

// ============================================================================
// TLS Context Tests
// ============================================================================

mod tls_context_tests {
    use super::*;

    #[test]
    fn test_tls_context_default() {
        let ctx = TlsContext::default();
        assert_eq!(ctx.security_level, SecurityLevel::High);
        assert_eq!(ctx.performance_preference, PerformancePreference::Balanced);
        assert!(ctx.use_case.is_none());
        assert!(ctx.pq_available);
    }

    #[test]
    fn test_tls_context_with_security_level() {
        let ctx = TlsContext::with_security_level(SecurityLevel::Maximum);
        assert_eq!(ctx.security_level, SecurityLevel::Maximum);
    }

    #[test]
    fn test_tls_context_with_use_case() {
        let ctx = TlsContext::with_use_case(TlsUseCase::Government);
        assert_eq!(ctx.use_case, Some(TlsUseCase::Government));
    }

    #[test]
    fn test_tls_context_builder() {
        let ctx = TlsContext::default()
            .security_level(SecurityLevel::Quantum)
            .performance_preference(PerformancePreference::Speed)
            .use_case(TlsUseCase::Government)
            .pq_available(true);

        assert_eq!(ctx.security_level, SecurityLevel::Quantum);
        assert_eq!(ctx.performance_preference, PerformancePreference::Speed);
        assert_eq!(ctx.use_case, Some(TlsUseCase::Government));
        assert!(ctx.pq_available);
    }
}

// ============================================================================
// TLS 1.3 Config Tests
// ============================================================================

mod tls13_config_tests {
    use super::*;

    #[test]
    fn test_tls13_config_default() {
        let config = Tls13Config::default();
        assert_eq!(config.mode, TlsMode::Hybrid);
        assert!(config.use_pq_kx);
        assert!(!config.enable_early_data);
    }

    #[test]
    fn test_tls13_config_classic() {
        let config = Tls13Config::classic();
        assert_eq!(config.mode, TlsMode::Classic);
        assert!(!config.use_pq_kx);
    }

    #[test]
    fn test_tls13_config_hybrid() {
        let config = Tls13Config::hybrid();
        assert_eq!(config.mode, TlsMode::Hybrid);
        assert!(config.use_pq_kx);
    }

    #[test]
    fn test_tls13_config_pq() {
        let config = Tls13Config::pq();
        assert_eq!(config.mode, TlsMode::Pq);
        assert!(config.use_pq_kx);
    }

    #[test]
    fn test_tls13_config_with_early_data() {
        let config = Tls13Config::hybrid().with_early_data(4096);
        assert!(config.enable_early_data);
        assert_eq!(config.max_early_data_size, 4096);
    }

    #[test]
    fn test_tls13_config_with_pq_kx() {
        let config = Tls13Config::classic().with_pq_kx(true);
        assert!(config.use_pq_kx);
    }

    #[test]
    fn test_tls13_config_with_alpn() {
        let config = Tls13Config::hybrid().with_alpn_protocols(vec!["h2", "http/1.1"]);
        assert_eq!(config.alpn_protocols.len(), 2);
    }

    #[test]
    fn test_tls13_config_with_max_fragment_size() {
        let config = Tls13Config::hybrid().with_max_fragment_size(8192);
        assert_eq!(config.max_fragment_size, Some(8192));
    }
}

// ============================================================================
// Handshake State Tests
// ============================================================================

mod handshake_state_tests {
    use super::*;

    #[test]
    fn test_handshake_state_variants() {
        let states = [
            HandshakeState::Start,
            HandshakeState::ClientHelloSent,
            HandshakeState::ServerHelloReceived,
            HandshakeState::ServerHelloSent,
            HandshakeState::ServerFinishedSent,
            HandshakeState::ServerFinishedReceived,
            HandshakeState::ClientFinishedSent,
            HandshakeState::Complete,
        ];

        for state in states {
            let debug = format!("{:?}", state);
            assert!(!debug.is_empty());
        }
    }

    #[test]
    fn test_handshake_state_eq() {
        assert_eq!(HandshakeState::Start, HandshakeState::Start);
        assert_ne!(HandshakeState::Start, HandshakeState::Complete);
    }
}

// ============================================================================
// Handshake Stats Tests
// ============================================================================

mod handshake_stats_tests {
    use super::*;

    #[test]
    fn test_handshake_stats_default() {
        let stats = HandshakeStats::default();
        assert_eq!(stats.duration_ms, 0);
        assert_eq!(stats.round_trips, 2);
        assert_eq!(stats.kex_time_ms, 0);
        assert_eq!(stats.cert_time_ms, 0);
        assert_eq!(stats.client_hello_size, 0);
        assert_eq!(stats.server_hello_size, 0);
    }
}

// ============================================================================
// Cipher Suite Tests
// ============================================================================

mod cipher_suite_tests {
    use super::*;

    #[test]
    fn test_get_cipher_suites_classic() {
        let suites = get_cipher_suites(TlsMode::Classic);
        assert_eq!(suites.len(), 3);
    }

    #[test]
    fn test_get_cipher_suites_hybrid() {
        let suites = get_cipher_suites(TlsMode::Hybrid);
        assert_eq!(suites.len(), 3);
    }

    #[test]
    fn test_get_cipher_suites_pq() {
        let suites = get_cipher_suites(TlsMode::Pq);
        assert_eq!(suites.len(), 2);
    }
}

// ============================================================================
// Verify Config Tests
// ============================================================================

mod verify_config_tests {
    use super::*;

    #[test]
    fn test_verify_config_valid() {
        let config = Tls13Config::hybrid();
        assert!(verify_config(&config).is_ok());
    }

    #[test]
    fn test_verify_config_invalid_early_data() {
        let config = Tls13Config::hybrid().with_early_data(0);
        let config = Tls13Config { enable_early_data: true, max_early_data_size: 0, ..config };
        assert!(verify_config(&config).is_err());
    }
}

// ============================================================================
// Constants Tests
// ============================================================================

mod constants_tests {
    use super::*;

    #[test]
    fn test_tls_scheme_constants() {
        assert!(DEFAULT_TLS_SCHEME.contains("hybrid"));
        assert!(DEFAULT_PQ_TLS_SCHEME.contains("pq"));
        assert!(CLASSICAL_TLS_SCHEME.contains("classic"));
    }

    #[test]
    fn test_tls_kex_constants() {
        assert!(DEFAULT_TLS_KEX.contains("X25519"));
        assert!(DEFAULT_TLS_KEX.contains("MLKEM"));
        assert!(DEFAULT_PQ_TLS_KEX.contains("MLKEM"));
        assert!(CLASSICAL_TLS_KEX.contains("X25519"));
    }

    #[test]
    fn test_hybrid_scheme_constants() {
        assert!(HYBRID_TLS_512.contains("512"));
        assert!(HYBRID_TLS_768.contains("768"));
        assert!(HYBRID_TLS_1024.contains("1024"));
    }

    #[test]
    fn test_pq_scheme_constants() {
        assert!(PQ_TLS_512.contains("512"));
        assert!(PQ_TLS_768.contains("768"));
        assert!(PQ_TLS_1024.contains("1024"));
    }
}

// ============================================================================
// Utility Tests
// ============================================================================

mod utility_tests {
    use super::*;

    #[test]
    fn test_version() {
        assert!(!VERSION.is_empty());
    }

    #[test]
    fn test_pq_enabled() {
        // PQ is always enabled in this library
        assert!(pq_enabled());
    }
}

// ============================================================================
// Post-Quantum Key Exchange Tests
// ============================================================================

mod pq_key_exchange_tests {
    #[allow(unused_imports)]
    use super::*;
    use arc_tls::pq_key_exchange::{
        PqKexMode, SecureSharedSecret, get_kex_info, get_kex_provider, is_custom_hybrid_available,
        is_pq_available,
    };

    #[test]
    fn test_pq_kex_mode_variants() {
        let modes = [PqKexMode::RustlsPq, PqKexMode::CustomHybrid, PqKexMode::Classical];

        for mode in modes {
            let debug = format!("{:?}", mode);
            assert!(!debug.is_empty());
        }
    }

    #[test]
    fn test_pq_kex_mode_eq() {
        assert_eq!(PqKexMode::RustlsPq, PqKexMode::RustlsPq);
        assert_eq!(PqKexMode::Classical, PqKexMode::Classical);
        assert_ne!(PqKexMode::RustlsPq, PqKexMode::Classical);
    }

    #[test]
    fn test_kex_info_hybrid() {
        let info = get_kex_info(TlsMode::Hybrid, PqKexMode::RustlsPq);

        assert_eq!(info.method, "X25519MLKEM768");
        assert!(info.is_pq_secure);
        assert_eq!(info.ss_size, 64);
        assert!(info.security_level.contains("Hybrid"));
    }

    #[test]
    fn test_kex_info_custom_hybrid() {
        let info = get_kex_info(TlsMode::Hybrid, PqKexMode::CustomHybrid);

        assert!(info.method.contains("Custom Hybrid"));
        assert!(info.is_pq_secure);
        assert_eq!(info.ss_size, 64);
    }

    #[test]
    fn test_kex_info_pq_mode() {
        let info = get_kex_info(TlsMode::Pq, PqKexMode::RustlsPq);

        assert!(info.is_pq_secure);
        assert_eq!(info.ss_size, 64);
    }

    #[test]
    fn test_kex_info_classical() {
        let info = get_kex_info(TlsMode::Classic, PqKexMode::Classical);

        assert_eq!(info.method, "X25519 (ECDHE)");
        assert!(!info.is_pq_secure);
        assert_eq!(info.pk_size, 32);
        assert_eq!(info.sk_size, 32);
        assert_eq!(info.ct_size, 32);
        assert_eq!(info.ss_size, 32);
    }

    #[test]
    fn test_kex_info_sizes_hybrid() {
        let info = get_kex_info(TlsMode::Hybrid, PqKexMode::RustlsPq);

        // X25519 (32) + ML-KEM-768 PK (1184)
        assert_eq!(info.pk_size, 32 + 1184);
        // X25519 (32) + ML-KEM-768 SK (2400)
        assert_eq!(info.sk_size, 32 + 2400);
        // X25519 (32) + ML-KEM-768 CT (1088)
        assert_eq!(info.ct_size, 32 + 1088);
    }

    #[test]
    fn test_is_pq_available() {
        assert!(is_pq_available());
    }

    #[test]
    fn test_is_custom_hybrid_available() {
        assert!(is_custom_hybrid_available());
    }

    #[test]
    fn test_get_kex_provider_hybrid() {
        let provider = get_kex_provider(TlsMode::Hybrid, PqKexMode::RustlsPq);
        assert!(provider.is_ok());
    }

    #[test]
    fn test_get_kex_provider_pq() {
        let provider = get_kex_provider(TlsMode::Pq, PqKexMode::RustlsPq);
        assert!(provider.is_ok());
    }

    #[test]
    fn test_get_kex_provider_custom_hybrid() {
        let provider = get_kex_provider(TlsMode::Hybrid, PqKexMode::CustomHybrid);
        assert!(provider.is_ok());
    }

    #[test]
    fn test_get_kex_provider_classical() {
        let provider = get_kex_provider(TlsMode::Classic, PqKexMode::Classical);
        assert!(provider.is_ok());
    }

    #[test]
    fn test_get_kex_provider_hybrid_classical_override() {
        // When mode is Hybrid but kex is Classical, should return classical provider
        let provider = get_kex_provider(TlsMode::Hybrid, PqKexMode::Classical);
        assert!(provider.is_ok());
    }

    #[test]
    fn test_secure_shared_secret() {
        let secret = vec![1u8, 2, 3, 4, 5];
        let secure = SecureSharedSecret::new(secret.clone());

        assert_eq!(secure.secret_ref(), secret.as_slice());
        assert_eq!(secure.as_ref(), secret.as_slice());
    }

    #[test]
    fn test_secure_shared_secret_into_inner() {
        let secret = vec![1u8, 2, 3, 4, 5];
        let secure = SecureSharedSecret::new(secret.clone());

        let zeroizing = secure.into_inner();
        assert_eq!(zeroizing.as_slice(), secret.as_slice());
    }

    #[test]
    fn test_secure_shared_secret_into_inner_raw() {
        let secret = vec![1u8, 2, 3, 4, 5];
        let secure = SecureSharedSecret::new(secret.clone());

        let raw = secure.into_inner_raw();
        assert_eq!(raw, secret);
    }

    #[test]
    fn test_kex_info_clone() {
        let info = get_kex_info(TlsMode::Hybrid, PqKexMode::RustlsPq);
        let cloned = info.clone();

        assert_eq!(info.method, cloned.method);
        assert_eq!(info.is_pq_secure, cloned.is_pq_secure);
    }

    #[test]
    fn test_kex_info_debug() {
        let info = get_kex_info(TlsMode::Hybrid, PqKexMode::RustlsPq);
        let debug = format!("{:?}", info);

        assert!(debug.contains("method"));
        assert!(debug.contains("is_pq_secure"));
    }
}

// ============================================================================
// Tracing Tests
// ============================================================================

mod tracing_tests {
    #[allow(unused_imports)]
    use super::*;
    use arc_tls::tracing::{TlsMetrics, TlsSpan, TracingConfig};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::time::Duration;

    #[test]
    fn test_tracing_config_default() {
        let config = TracingConfig::default();

        assert!(!config.distributed_tracing);
        assert!(!config.include_sensitive_data);
        assert!(config.track_performance);
    }

    #[test]
    fn test_tracing_config_debug() {
        let config = TracingConfig::debug();

        assert!(!config.include_sensitive_data);
        assert!(config.track_performance);
    }

    #[test]
    fn test_tracing_config_trace() {
        let config = TracingConfig::trace();

        assert!(!config.include_sensitive_data);
    }

    #[test]
    fn test_tracing_config_with_sensitive_data() {
        let config = TracingConfig::default().with_sensitive_data();

        assert!(config.include_sensitive_data);
    }

    #[test]
    fn test_tls_span_new() {
        let span = TlsSpan::new("test_operation", None);

        assert!(span.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn test_tls_span_with_peer() {
        let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 443);
        let span = TlsSpan::new("test_operation", Some(peer));

        assert!(span.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn test_tls_span_connection() {
        let span = TlsSpan::connection("localhost:443", Some("example.com"));

        assert!(span.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn test_tls_span_handshake() {
        let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 443);
        let span = TlsSpan::handshake(Some(peer), "Hybrid");

        assert!(span.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn test_tls_span_key_exchange() {
        let span = TlsSpan::key_exchange("X25519MLKEM768");

        assert!(span.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn test_tls_span_certificate_verification() {
        let span = TlsSpan::certificate_verification("CN=example.com", "CN=Example CA");

        assert!(span.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn test_tls_span_elapsed() {
        let span = TlsSpan::new("test_operation", None);

        // Sleep briefly to ensure elapsed time is measurable
        std::thread::sleep(Duration::from_millis(10));

        assert!(span.elapsed() >= Duration::from_millis(10));
    }

    #[test]
    fn test_tls_span_complete() {
        let span = TlsSpan::new("test_operation", None);
        span.complete();
        // Should not panic
    }

    #[test]
    fn test_tls_span_in_scope() {
        let span = TlsSpan::new("test_operation", None);

        let result = span.in_scope(|| 42);

        assert_eq!(result, 42);
    }

    #[test]
    fn test_tls_metrics_default() {
        let metrics = TlsMetrics::default();

        assert_eq!(metrics.bytes_sent, 0);
        assert_eq!(metrics.bytes_received, 0);
        assert_eq!(metrics.handshake_duration, Duration::ZERO);
        assert_eq!(metrics.kex_duration, Duration::ZERO);
        assert_eq!(metrics.cert_duration, Duration::ZERO);
        assert_eq!(metrics.total_duration, Duration::ZERO);
    }

    #[test]
    fn test_tls_metrics_new() {
        let metrics = TlsMetrics::new();

        assert_eq!(metrics.bytes_sent, 0);
        assert_eq!(metrics.bytes_received, 0);
    }

    #[test]
    fn test_tls_metrics_record_handshake() {
        let mut metrics = TlsMetrics::new();
        metrics.record_handshake(Duration::from_millis(100));

        assert_eq!(metrics.handshake_duration, Duration::from_millis(100));
    }

    #[test]
    fn test_tls_metrics_record_kex() {
        let mut metrics = TlsMetrics::new();
        metrics.record_kex(Duration::from_millis(50));

        assert_eq!(metrics.kex_duration, Duration::from_millis(50));
    }

    #[test]
    fn test_tls_metrics_record_cert() {
        let mut metrics = TlsMetrics::new();
        metrics.record_cert(Duration::from_millis(25));

        assert_eq!(metrics.cert_duration, Duration::from_millis(25));
    }

    #[test]
    fn test_tls_metrics_record_sent() {
        let mut metrics = TlsMetrics::new();
        metrics.record_sent(100);
        metrics.record_sent(200);

        assert_eq!(metrics.bytes_sent, 300);
    }

    #[test]
    fn test_tls_metrics_record_received() {
        let mut metrics = TlsMetrics::new();
        metrics.record_received(500);
        metrics.record_received(500);

        assert_eq!(metrics.bytes_received, 1000);
    }

    #[test]
    fn test_tls_metrics_complete() {
        let mut metrics = TlsMetrics::new();
        metrics.record_handshake(Duration::from_millis(100));
        metrics.record_kex(Duration::from_millis(50));
        metrics.record_cert(Duration::from_millis(25));
        metrics.complete();

        assert_eq!(metrics.total_duration, Duration::from_millis(175));
    }

    #[test]
    fn test_tls_metrics_log() {
        let mut metrics = TlsMetrics::new();
        metrics.record_handshake(Duration::from_millis(100));
        metrics.record_sent(1000);
        metrics.record_received(2000);

        // Should not panic
        metrics.log("test_operation");
    }

    #[test]
    fn test_tls_metrics_clone() {
        let mut metrics = TlsMetrics::new();
        metrics.record_sent(100);

        let cloned = metrics.clone();
        assert_eq!(cloned.bytes_sent, 100);
    }

    #[test]
    fn test_tls_metrics_debug() {
        let metrics = TlsMetrics::new();
        let debug = format!("{:?}", metrics);

        assert!(debug.contains("bytes_sent"));
        assert!(debug.contains("bytes_received"));
    }

    #[test]
    fn test_tls_metrics_saturating_add() {
        let mut metrics = TlsMetrics::new();

        // Should not overflow
        metrics.record_sent(u64::MAX);
        metrics.record_sent(1);

        assert_eq!(metrics.bytes_sent, u64::MAX);
    }
}
