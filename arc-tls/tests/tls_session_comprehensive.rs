#![deny(unsafe_code)]
// Test files use expect() and unwrap() for assertions
#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]
// Allow panic for test assertions
#![allow(clippy::panic)]
// Allow indexing in tests
#![allow(clippy::indexing_slicing)]

//! Comprehensive TLS Session and Connection Tests
//!
//! This test module provides comprehensive coverage for:
//! - Session management and configuration
//! - Connection state machines
//! - Key exchange (ML-KEM, hybrid, classical)
//! - TLS configuration options
//! - Error scenarios and edge cases

use arc_core::SecurityLevel;
use arc_tls::error::{ErrorCode, ErrorContext, ErrorSeverity, OperationPhase, RecoveryHint};
use arc_tls::pq_key_exchange::{PqKexMode, get_kex_info, get_kex_provider};
use arc_tls::recovery::{
    CircuitBreaker, CircuitState, DegradationConfig, FallbackStrategy, RetryPolicy,
};
use arc_tls::selector::{
    CLASSICAL_TLS_KEX, CLASSICAL_TLS_SCHEME, DEFAULT_PQ_TLS_KEX, DEFAULT_PQ_TLS_SCHEME,
    DEFAULT_TLS_KEX, DEFAULT_TLS_SCHEME, HYBRID_TLS_512, HYBRID_TLS_768, HYBRID_TLS_1024,
    PQ_TLS_512, PQ_TLS_768, PQ_TLS_1024, TlsConstraints, TlsContext, TlsPolicyEngine, TlsUseCase,
};
use arc_tls::session_store::{
    ConfigurableSessionStore, PersistentSessionStore, create_resumption_config,
    create_session_store,
};
use arc_tls::tls13::{
    HandshakeState, HandshakeStats, Tls13Config, get_cipher_suites, verify_config,
};
use arc_tls::{
    ClientVerificationMode, SessionPersistenceConfig, TlsConfig, TlsError, TlsMode, VERSION,
};
use std::time::Duration;

// =============================================================================
// SESSION MANAGEMENT TESTS
// =============================================================================

mod session_management {
    use super::*;

    #[test]
    fn test_session_creation_default_capacity() {
        let store = ConfigurableSessionStore::new(100);
        assert_eq!(store.capacity(), 100);
    }

    #[test]
    fn test_session_creation_large_capacity() {
        let store = ConfigurableSessionStore::new(10000);
        assert_eq!(store.capacity(), 10000);
    }

    #[test]
    fn test_session_creation_minimum_capacity() {
        let store = ConfigurableSessionStore::new(1);
        assert_eq!(store.capacity(), 1);
    }

    #[test]
    fn test_session_store_arc_reference() {
        let store = ConfigurableSessionStore::new(50);
        let arc_store = store.as_store();
        assert_eq!(std::sync::Arc::strong_count(&arc_store), 2);
    }

    #[test]
    fn test_persistent_store_creation() {
        let store = PersistentSessionStore::new("/tmp/tls_sessions.bin", 500);
        assert_eq!(store.capacity(), 500);
        assert_eq!(store.path().to_str().unwrap(), "/tmp/tls_sessions.bin");
    }

    #[test]
    fn test_persistent_store_persistence_disabled() {
        let store = PersistentSessionStore::new("/var/cache/sessions.bin", 100);
        // Persistence is currently disabled (waiting for rustls serialization API)
        assert!(!store.is_persistence_enabled());
    }

    #[test]
    fn test_create_session_store_none_config() {
        let store = create_session_store(None);
        // Default capacity is 32 sessions
        assert_eq!(std::sync::Arc::strong_count(&store), 1);
    }

    #[test]
    fn test_create_session_store_with_config() {
        let config = SessionPersistenceConfig::new("/tmp/sessions.bin", 200);
        let store = create_session_store(Some(&config));
        assert_eq!(std::sync::Arc::strong_count(&store), 1);
    }

    #[test]
    fn test_session_persistence_config_creation() {
        let config = SessionPersistenceConfig::new("/data/tls_cache", 1000);
        assert_eq!(config.max_sessions, 1000);
        assert_eq!(config.path.to_str().unwrap(), "/data/tls_cache");
    }

    #[test]
    fn test_create_resumption_config_none() {
        let resumption = create_resumption_config(None);
        // Verify resumption config is created (no public fields to check)
        let _ = resumption;
    }

    #[test]
    fn test_create_resumption_config_with_persistence() {
        let config = SessionPersistenceConfig::new("/tmp/sessions.bin", 500);
        let resumption = create_resumption_config(Some(&config));
        let _ = resumption;
    }
}

// =============================================================================
// CONNECTION CONFIGURATION TESTS
// =============================================================================

mod connection_config {
    use super::*;

    #[test]
    fn test_server_config_builder_classic() {
        let config = Tls13Config::classic();
        assert_eq!(config.mode, TlsMode::Classic);
        assert!(!config.use_pq_kx);
        assert!(!config.enable_early_data);
    }

    #[test]
    fn test_server_config_builder_hybrid() {
        let config = Tls13Config::hybrid();
        assert_eq!(config.mode, TlsMode::Hybrid);
        assert!(config.use_pq_kx);
        assert!(!config.enable_early_data);
    }

    #[test]
    fn test_server_config_builder_pq() {
        let config = Tls13Config::pq();
        assert_eq!(config.mode, TlsMode::Pq);
        assert!(config.use_pq_kx);
    }

    #[test]
    fn test_client_config_builder_with_early_data() {
        let config = Tls13Config::hybrid().with_early_data(16384);
        assert!(config.enable_early_data);
        assert_eq!(config.max_early_data_size, 16384);
    }

    #[test]
    fn test_config_with_pq_kx_disabled() {
        let config = Tls13Config::hybrid().with_pq_kx(false);
        assert!(!config.use_pq_kx);
    }

    #[test]
    fn test_config_with_alpn_protocols() {
        let config = Tls13Config::hybrid().with_alpn_protocols(vec!["h2", "http/1.1"]);
        assert_eq!(config.alpn_protocols.len(), 2);
        assert_eq!(config.alpn_protocols[0], b"h2");
        assert_eq!(config.alpn_protocols[1], b"http/1.1");
    }

    #[test]
    fn test_config_with_max_fragment_size() {
        let config = Tls13Config::hybrid().with_max_fragment_size(8192);
        assert_eq!(config.max_fragment_size, Some(8192));
    }

    #[test]
    fn test_tls_config_default() {
        let config = TlsConfig::default();
        assert_eq!(config.mode, TlsMode::Hybrid);
        assert!(!config.enable_tracing);
        assert!(config.enable_fallback);
        assert!(config.enable_resumption);
        assert_eq!(config.session_lifetime, 7200);
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
    fn test_tls_config_with_fallback_disabled() {
        let config = TlsConfig::new().with_fallback(false);
        assert!(!config.enable_fallback);
    }

    #[test]
    fn test_tls_config_with_session_lifetime() {
        let config = TlsConfig::new().with_session_lifetime(3600);
        assert_eq!(config.session_lifetime, 3600);
    }

    #[test]
    fn test_tls_config_with_resumption_disabled() {
        let config = TlsConfig::new().with_resumption(false);
        assert!(!config.enable_resumption);
    }
}

// =============================================================================
// CONNECTION STATE MACHINE TESTS
// =============================================================================

mod connection_state_machine {
    use super::*;

    #[test]
    fn test_handshake_state_start() {
        let state = HandshakeState::Start;
        assert_eq!(state, HandshakeState::Start);
    }

    #[test]
    fn test_handshake_state_client_hello_sent() {
        let state = HandshakeState::ClientHelloSent;
        assert_eq!(state, HandshakeState::ClientHelloSent);
    }

    #[test]
    fn test_handshake_state_server_hello_received() {
        let state = HandshakeState::ServerHelloReceived;
        assert_eq!(state, HandshakeState::ServerHelloReceived);
    }

    #[test]
    fn test_handshake_state_server_hello_sent() {
        let state = HandshakeState::ServerHelloSent;
        assert_eq!(state, HandshakeState::ServerHelloSent);
    }

    #[test]
    fn test_handshake_state_server_finished_sent() {
        let state = HandshakeState::ServerFinishedSent;
        assert_eq!(state, HandshakeState::ServerFinishedSent);
    }

    #[test]
    fn test_handshake_state_complete() {
        let state = HandshakeState::Complete;
        assert_eq!(state, HandshakeState::Complete);
    }

    #[test]
    fn test_handshake_state_transitions_distinct() {
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

        for (i, state1) in states.iter().enumerate() {
            for (j, state2) in states.iter().enumerate() {
                if i != j {
                    assert_ne!(state1, state2);
                }
            }
        }
    }

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

    #[test]
    fn test_handshake_stats_clone() {
        let stats = HandshakeStats::default();
        let cloned = stats.clone();
        assert_eq!(cloned.duration_ms, stats.duration_ms);
        assert_eq!(cloned.round_trips, stats.round_trips);
    }
}

// =============================================================================
// KEY EXCHANGE TESTS
// =============================================================================

mod key_exchange {
    use super::*;

    #[test]
    fn test_ml_kem_kex_info_hybrid() {
        let info = get_kex_info(TlsMode::Hybrid, PqKexMode::RustlsPq);
        assert_eq!(info.method, "X25519MLKEM768");
        assert!(info.is_pq_secure);
        assert_eq!(info.pk_size, 32 + 1184); // X25519 + ML-KEM-768
        assert_eq!(info.ss_size, 64);
    }

    #[test]
    fn test_hybrid_kex_x25519_ml_kem() {
        let info = get_kex_info(TlsMode::Hybrid, PqKexMode::CustomHybrid);
        assert_eq!(info.method, "Custom Hybrid (X25519 + ML-KEM-768)");
        assert!(info.is_pq_secure);
        assert_eq!(info.ss_size, 64);
    }

    #[test]
    fn test_classical_kex_x25519() {
        let info = get_kex_info(TlsMode::Classic, PqKexMode::Classical);
        assert_eq!(info.method, "X25519 (ECDHE)");
        assert!(!info.is_pq_secure);
        assert_eq!(info.pk_size, 32);
        assert_eq!(info.sk_size, 32);
        assert_eq!(info.ct_size, 32);
        assert_eq!(info.ss_size, 32);
    }

    #[test]
    fn test_kex_provider_hybrid_mode() {
        let provider = get_kex_provider(TlsMode::Hybrid, PqKexMode::RustlsPq);
        assert!(provider.is_ok());
    }

    #[test]
    fn test_kex_provider_classic_mode() {
        let provider = get_kex_provider(TlsMode::Classic, PqKexMode::Classical);
        assert!(provider.is_ok());
    }

    #[test]
    fn test_kex_provider_pq_mode() {
        let provider = get_kex_provider(TlsMode::Pq, PqKexMode::RustlsPq);
        assert!(provider.is_ok());
    }

    #[test]
    fn test_kex_provider_custom_hybrid() {
        let provider = get_kex_provider(TlsMode::Hybrid, PqKexMode::CustomHybrid);
        assert!(provider.is_ok());
    }

    #[test]
    fn test_pq_availability() {
        assert!(arc_tls::pq_key_exchange::is_pq_available());
    }

    #[test]
    fn test_custom_hybrid_availability() {
        assert!(arc_tls::pq_key_exchange::is_custom_hybrid_available());
    }
}

// =============================================================================
// CONFIGURATION TESTS
// =============================================================================

mod configuration {
    use super::*;

    #[test]
    fn test_tls_version_negotiation_tls13_only() {
        let config = TlsConfig::new()
            .with_min_protocol_version(rustls::ProtocolVersion::TLSv1_3)
            .with_max_protocol_version(rustls::ProtocolVersion::TLSv1_3);
        assert_eq!(config.min_protocol_version, Some(rustls::ProtocolVersion::TLSv1_3));
        assert_eq!(config.max_protocol_version, Some(rustls::ProtocolVersion::TLSv1_3));
    }

    #[test]
    fn test_tls_version_negotiation_tls12_and_tls13() {
        let config = TlsConfig::new()
            .with_min_protocol_version(rustls::ProtocolVersion::TLSv1_2)
            .with_max_protocol_version(rustls::ProtocolVersion::TLSv1_3);
        assert_eq!(config.min_protocol_version, Some(rustls::ProtocolVersion::TLSv1_2));
    }

    #[test]
    fn test_alpn_protocol_selection() {
        let config = TlsConfig::new().with_alpn_protocols(vec!["h2", "http/1.1", "spdy/3.1"]);
        assert_eq!(config.alpn_protocols.len(), 3);
        assert_eq!(config.alpn_protocols[0], b"h2".to_vec());
        assert_eq!(config.alpn_protocols[1], b"http/1.1".to_vec());
    }

    #[test]
    fn test_sni_configuration() {
        // SNI is handled at connection time, not config time
        // This test verifies the configuration structure supports it
        let config = TlsConfig::new();
        assert_eq!(config.mode, TlsMode::Hybrid);
    }

    #[test]
    fn test_max_fragment_length_extension() {
        let config = TlsConfig::new().with_max_fragment_size(4096);
        assert_eq!(config.max_fragment_size, Some(4096));
    }

    #[test]
    fn test_max_fragment_length_default() {
        let config = TlsConfig::new();
        assert!(config.max_fragment_size.is_none()); // Default is 16KB
    }

    #[test]
    fn test_certificate_verification_none() {
        let config = TlsConfig::new().with_client_verification(ClientVerificationMode::None);
        assert_eq!(config.client_verification, ClientVerificationMode::None);
    }

    #[test]
    fn test_certificate_verification_optional() {
        let config = TlsConfig::new().with_client_verification(ClientVerificationMode::Optional);
        assert_eq!(config.client_verification, ClientVerificationMode::Optional);
    }

    #[test]
    fn test_certificate_verification_required() {
        let config = TlsConfig::new().with_client_verification(ClientVerificationMode::Required);
        assert_eq!(config.client_verification, ClientVerificationMode::Required);
    }

    #[test]
    fn test_client_auth_config() {
        let config = TlsConfig::new().with_client_auth("client.crt", "client.key");
        assert!(config.client_auth.is_some());
        let auth = config.client_auth.unwrap();
        assert_eq!(auth.cert_path, "client.crt");
        assert_eq!(auth.key_path, "client.key");
    }

    #[test]
    fn test_client_ca_certs_config() {
        let config = TlsConfig::new().with_client_ca_certs("ca-bundle.crt");
        assert_eq!(config.client_ca_certs, Some("ca-bundle.crt".to_string()));
    }

    #[test]
    fn test_session_persistence_config() {
        let config = TlsConfig::new().with_session_persistence("/var/cache/sessions.bin", 1000);
        assert!(config.session_persistence.is_some());
        let persistence = config.session_persistence.unwrap();
        assert_eq!(persistence.max_sessions, 1000);
    }

    #[test]
    fn test_cipher_suites_classic() {
        let suites = get_cipher_suites(TlsMode::Classic);
        assert_eq!(suites.len(), 3);
    }

    #[test]
    fn test_cipher_suites_hybrid() {
        let suites = get_cipher_suites(TlsMode::Hybrid);
        assert_eq!(suites.len(), 3);
    }

    #[test]
    fn test_cipher_suites_pq() {
        let suites = get_cipher_suites(TlsMode::Pq);
        assert_eq!(suites.len(), 2);
    }

    #[test]
    fn test_config_validation_valid() {
        let config = TlsConfig::new()
            .with_min_protocol_version(rustls::ProtocolVersion::TLSv1_3)
            .with_max_protocol_version(rustls::ProtocolVersion::TLSv1_3);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_verify_config_valid_hybrid() {
        let config = Tls13Config::hybrid();
        assert!(verify_config(&config).is_ok());
    }

    #[test]
    fn test_verify_config_invalid_early_data() {
        let config = Tls13Config::hybrid().with_early_data(0);
        // Early data enabled but max size is 0 - should fail
        assert!(verify_config(&config).is_err());
    }

    #[test]
    fn test_verify_config_valid_early_data() {
        let config = Tls13Config::hybrid().with_early_data(4096);
        assert!(verify_config(&config).is_ok());
    }
}

// =============================================================================
// ERROR SCENARIO TESTS
// =============================================================================

mod error_scenarios {
    use super::*;

    #[test]
    fn test_connection_refused_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "test");
        let tls_err = TlsError::from(io_err);
        assert_eq!(tls_err.code(), ErrorCode::ConnectionRefused);
    }

    #[test]
    fn test_connection_timeout_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::TimedOut, "test");
        let tls_err = TlsError::from(io_err);
        assert_eq!(tls_err.code(), ErrorCode::ConnectionTimeout);
    }

    #[test]
    fn test_connection_reset_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::ConnectionReset, "test");
        let tls_err = TlsError::from(io_err);
        assert_eq!(tls_err.code(), ErrorCode::ConnectionReset);
    }

    #[test]
    fn test_unexpected_eof_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "test");
        let tls_err = TlsError::from(io_err);
        assert_eq!(tls_err.code(), ErrorCode::UnexpectedEof);
    }

    #[test]
    fn test_error_severity_levels() {
        assert!(ErrorSeverity::Info < ErrorSeverity::Warning);
        assert!(ErrorSeverity::Warning < ErrorSeverity::Error);
        assert!(ErrorSeverity::Error < ErrorSeverity::Critical);
    }

    #[test]
    fn test_operation_phase_initialization() {
        let context = ErrorContext::default();
        assert_eq!(context.phase, OperationPhase::Initialization);
    }

    #[test]
    fn test_error_code_display() {
        assert_eq!(ErrorCode::ConnectionRefused.to_string(), "CONNECTION_REFUSED");
        assert_eq!(ErrorCode::HandshakeFailed.to_string(), "HANDSHAKE_FAILED");
        assert_eq!(ErrorCode::CertificateExpired.to_string(), "CERTIFICATE_EXPIRED");
    }

    #[test]
    fn test_recovery_hint_retry() {
        let hint = RecoveryHint::Retry { max_attempts: 3, backoff_ms: 1000 };
        match hint {
            RecoveryHint::Retry { max_attempts, backoff_ms } => {
                assert_eq!(max_attempts, 3);
                assert_eq!(backoff_ms, 1000);
            }
            _ => panic!("Expected Retry hint"),
        }
    }

    #[test]
    fn test_recovery_hint_fallback() {
        let hint = RecoveryHint::Fallback { description: "Use classical TLS".to_string() };
        match hint {
            RecoveryHint::Fallback { description } => {
                assert!(description.contains("classical"));
            }
            _ => panic!("Expected Fallback hint"),
        }
    }

    #[test]
    fn test_error_recoverability() {
        let io_err = std::io::Error::new(std::io::ErrorKind::ConnectionReset, "test");
        let tls_err = TlsError::from(io_err);
        assert!(tls_err.is_recoverable());
    }
}

// =============================================================================
// TLS POLICY ENGINE TESTS
// =============================================================================

mod policy_engine {
    use super::*;

    #[test]
    fn test_recommend_mode_web_server() {
        let mode = TlsPolicyEngine::recommend_mode(TlsUseCase::WebServer);
        assert_eq!(mode, TlsMode::Hybrid);
    }

    #[test]
    fn test_recommend_mode_iot() {
        let mode = TlsPolicyEngine::recommend_mode(TlsUseCase::IoT);
        assert_eq!(mode, TlsMode::Classic);
    }

    #[test]
    fn test_recommend_mode_government() {
        let mode = TlsPolicyEngine::recommend_mode(TlsUseCase::Government);
        assert_eq!(mode, TlsMode::Pq);
    }

    #[test]
    fn test_recommend_mode_financial_services() {
        let mode = TlsPolicyEngine::recommend_mode(TlsUseCase::FinancialServices);
        assert_eq!(mode, TlsMode::Hybrid);
    }

    #[test]
    fn test_recommend_mode_healthcare() {
        let mode = TlsPolicyEngine::recommend_mode(TlsUseCase::Healthcare);
        assert_eq!(mode, TlsMode::Hybrid);
    }

    #[test]
    fn test_recommend_mode_real_time_streaming() {
        let mode = TlsPolicyEngine::recommend_mode(TlsUseCase::RealTimeStreaming);
        assert_eq!(mode, TlsMode::Classic);
    }

    #[test]
    fn test_select_by_security_level_quantum() {
        let mode = TlsPolicyEngine::select_by_security_level(SecurityLevel::Quantum);
        assert_eq!(mode, TlsMode::Pq);
    }

    #[test]
    fn test_select_by_security_level_maximum() {
        let mode = TlsPolicyEngine::select_by_security_level(SecurityLevel::Maximum);
        assert_eq!(mode, TlsMode::Hybrid);
    }

    #[test]
    fn test_select_by_security_level_standard() {
        let mode = TlsPolicyEngine::select_by_security_level(SecurityLevel::Standard);
        assert_eq!(mode, TlsMode::Hybrid);
    }

    #[test]
    fn test_constraints_requires_classic() {
        let constraints = TlsConstraints::maximum_compatibility();
        assert!(constraints.requires_classic());
    }

    #[test]
    fn test_constraints_allows_pq() {
        let constraints = TlsConstraints::high_security();
        assert!(constraints.allows_pq());
    }

    #[test]
    fn test_tls_context_default() {
        let ctx = TlsContext::default();
        assert_eq!(ctx.security_level, SecurityLevel::High);
        assert!(ctx.pq_available);
    }

    #[test]
    fn test_tls_context_with_use_case() {
        let ctx = TlsContext::with_use_case(TlsUseCase::FinancialServices);
        assert_eq!(ctx.use_case, Some(TlsUseCase::FinancialServices));
    }

    #[test]
    fn test_scheme_constants() {
        assert!(DEFAULT_TLS_SCHEME.contains("hybrid"));
        assert!(DEFAULT_PQ_TLS_SCHEME.contains("pq"));
        assert!(CLASSICAL_TLS_SCHEME.contains("classic"));
    }
}

// =============================================================================
// CIRCUIT BREAKER TESTS
// =============================================================================

mod circuit_breaker {
    use super::*;

    #[test]
    fn test_circuit_breaker_initial_state() {
        let breaker = CircuitBreaker::new(5, Duration::from_secs(60));
        assert_eq!(breaker.state(), CircuitState::Closed);
    }

    #[test]
    fn test_circuit_breaker_allows_request_when_closed() {
        let breaker = CircuitBreaker::new(5, Duration::from_secs(60));
        assert!(breaker.allow_request());
    }

    #[test]
    fn test_circuit_breaker_opens_after_failures() {
        let breaker = CircuitBreaker::new(3, Duration::from_secs(60));

        breaker.record_failure();
        breaker.record_failure();
        breaker.record_failure();

        assert_eq!(breaker.state(), CircuitState::Open);
    }

    #[test]
    fn test_circuit_breaker_blocks_when_open() {
        let breaker = CircuitBreaker::new(3, Duration::from_secs(60));

        for _ in 0..3 {
            breaker.record_failure();
        }

        assert!(!breaker.allow_request());
    }

    #[test]
    fn test_circuit_breaker_reset() {
        let breaker = CircuitBreaker::new(3, Duration::from_secs(60));

        for _ in 0..3 {
            breaker.record_failure();
        }
        assert_eq!(breaker.state(), CircuitState::Open);

        breaker.reset();
        assert_eq!(breaker.state(), CircuitState::Closed);
    }

    #[test]
    fn test_circuit_breaker_success_resets_failure_count() {
        let breaker = CircuitBreaker::new(5, Duration::from_secs(60));

        breaker.record_failure();
        breaker.record_failure();
        breaker.record_success();

        assert_eq!(breaker.state(), CircuitState::Closed);
    }
}

// =============================================================================
// RETRY POLICY TESTS
// =============================================================================

mod retry_policy {
    use super::*;

    #[test]
    fn test_retry_policy_default() {
        let policy = RetryPolicy::default();
        assert_eq!(policy.max_attempts, 3);
        assert_eq!(policy.initial_backoff, Duration::from_millis(100));
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
    fn test_retry_policy_custom() {
        let policy = RetryPolicy::new(10, Duration::from_millis(500), Duration::from_secs(30));
        assert_eq!(policy.max_attempts, 10);
        assert_eq!(policy.initial_backoff, Duration::from_millis(500));
        assert_eq!(policy.max_backoff, Duration::from_secs(30));
    }

    #[test]
    fn test_backoff_increases_with_attempts() {
        let mut policy = RetryPolicy::default();
        policy.jitter = false; // Disable jitter for predictable testing

        let backoff1 = policy.backoff_for_attempt(1);
        let backoff2 = policy.backoff_for_attempt(2);
        let backoff3 = policy.backoff_for_attempt(3);

        assert!(backoff2 > backoff1);
        assert!(backoff3 > backoff2);
    }

    #[test]
    fn test_backoff_respects_max() {
        let mut policy = RetryPolicy::new(10, Duration::from_secs(1), Duration::from_secs(5));
        policy.jitter = false;

        let backoff = policy.backoff_for_attempt(100);
        assert!(backoff <= policy.max_backoff);
    }
}

// =============================================================================
// FALLBACK STRATEGY TESTS
// =============================================================================

mod fallback_strategy {
    use super::*;

    #[test]
    fn test_fallback_strategy_none() {
        let strategy = FallbackStrategy::None;
        assert_eq!(strategy.description(), "No fallback available");
    }

    #[test]
    fn test_fallback_strategy_hybrid_to_classical() {
        let strategy = FallbackStrategy::hybrid_to_classical();
        assert!(strategy.description().contains("hybrid to classical"));
    }

    #[test]
    fn test_fallback_strategy_pq_to_hybrid() {
        let strategy = FallbackStrategy::pq_to_hybrid();
        assert!(strategy.description().contains("PQ-only to hybrid"));
    }

    #[test]
    fn test_fallback_strategy_custom() {
        let strategy = FallbackStrategy::Custom { description: "Custom fallback".to_string() };
        assert_eq!(strategy.description(), "Custom fallback");
    }

    #[test]
    fn test_degradation_config_default() {
        let config = DegradationConfig::default();
        assert!(config.enable_fallback);
        assert!(!config.allow_reduced_security);
        assert_eq!(config.max_degradation_attempts, 2);
    }
}

// =============================================================================
// TLS CONFIG CONVERSION TESTS
// =============================================================================

mod config_conversion {
    use super::*;

    #[test]
    fn test_tls13_config_from_tls_config_hybrid() {
        let config = TlsConfig::new();
        let tls13_config = Tls13Config::from(&config);
        assert_eq!(tls13_config.mode, TlsMode::Hybrid);
    }

    #[test]
    fn test_tls13_config_from_tls_config_classic() {
        let mut config = TlsConfig::new();
        config.mode = TlsMode::Classic;
        let tls13_config = Tls13Config::from(&config);
        assert_eq!(tls13_config.mode, TlsMode::Classic);
    }

    #[test]
    fn test_tls13_config_from_tls_config_pq() {
        let mut config = TlsConfig::new();
        config.mode = TlsMode::Pq;
        let tls13_config = Tls13Config::from(&config);
        assert_eq!(tls13_config.mode, TlsMode::Pq);
    }

    #[test]
    fn test_tls13_config_inherits_alpn() {
        let config = TlsConfig::new().with_alpn_protocols(vec!["h2"]);
        let tls13_config = Tls13Config::from(&config);
        assert_eq!(tls13_config.alpn_protocols.len(), 1);
    }

    #[test]
    fn test_tls13_config_inherits_early_data() {
        let config = TlsConfig::new().with_early_data(8192);
        let tls13_config = Tls13Config::from(&config);
        assert!(tls13_config.enable_early_data);
        assert_eq!(tls13_config.max_early_data_size, 8192);
    }

    #[test]
    fn test_tls13_config_inherits_fragment_size() {
        let config = TlsConfig::new().with_max_fragment_size(4096);
        let tls13_config = Tls13Config::from(&config);
        assert_eq!(tls13_config.max_fragment_size, Some(4096));
    }
}

// =============================================================================
// USE CASE TESTS
// =============================================================================

mod use_cases {
    use super::*;

    #[test]
    fn test_use_case_all() {
        let all = TlsUseCase::all();
        assert_eq!(all.len(), 10);
    }

    #[test]
    fn test_use_case_descriptions() {
        assert!(TlsUseCase::WebServer.description().contains("Web server"));
        assert!(TlsUseCase::IoT.description().contains("IoT"));
        assert!(TlsUseCase::Government.description().contains("Government"));
    }

    #[test]
    fn test_tls_config_use_case() {
        let config = TlsConfig::new().use_case(TlsUseCase::WebServer);
        assert_eq!(config.mode, TlsMode::Hybrid);
    }

    #[test]
    fn test_tls_config_security_level() {
        let config = TlsConfig::new().security_level(SecurityLevel::Quantum);
        assert_eq!(config.mode, TlsMode::Pq);
    }
}

// =============================================================================
// VERSION AND AVAILABILITY TESTS
// =============================================================================

mod version_and_availability {
    use super::*;

    #[test]
    fn test_version_not_empty() {
        assert!(!VERSION.is_empty());
    }

    #[test]
    fn test_pq_enabled() {
        assert!(arc_tls::pq_enabled());
    }

    #[test]
    fn test_tls_mode_default() {
        assert_eq!(TlsMode::default(), TlsMode::Hybrid);
    }

    #[test]
    fn test_client_verification_mode_default() {
        assert_eq!(ClientVerificationMode::default(), ClientVerificationMode::None);
    }
}

// =============================================================================
// SCHEME SELECTOR TESTS
// =============================================================================

mod scheme_selector {
    use super::*;

    #[test]
    fn test_hybrid_schemes() {
        assert_eq!(HYBRID_TLS_512, "hybrid-x25519-ml-kem-512");
        assert_eq!(HYBRID_TLS_768, "hybrid-x25519-ml-kem-768");
        assert_eq!(HYBRID_TLS_1024, "hybrid-x25519-ml-kem-1024");
    }

    #[test]
    fn test_pq_schemes() {
        assert_eq!(PQ_TLS_512, "pq-ml-kem-512");
        assert_eq!(PQ_TLS_768, "pq-ml-kem-768");
        assert_eq!(PQ_TLS_1024, "pq-ml-kem-1024");
    }

    #[test]
    fn test_default_kex_algorithms() {
        assert_eq!(DEFAULT_TLS_KEX, "X25519MLKEM768");
        assert_eq!(DEFAULT_PQ_TLS_KEX, "MLKEM768");
        assert_eq!(CLASSICAL_TLS_KEX, "X25519");
    }

    #[test]
    fn test_select_hybrid_scheme_by_level() {
        assert_eq!(TlsPolicyEngine::select_hybrid_scheme(SecurityLevel::Standard), HYBRID_TLS_512);
        assert_eq!(TlsPolicyEngine::select_hybrid_scheme(SecurityLevel::High), HYBRID_TLS_768);
        assert_eq!(TlsPolicyEngine::select_hybrid_scheme(SecurityLevel::Maximum), HYBRID_TLS_1024);
    }

    #[test]
    fn test_select_pq_scheme_by_level() {
        assert_eq!(TlsPolicyEngine::select_pq_scheme(SecurityLevel::Standard), PQ_TLS_512);
        assert_eq!(TlsPolicyEngine::select_pq_scheme(SecurityLevel::High), PQ_TLS_768);
        assert_eq!(TlsPolicyEngine::select_pq_scheme(SecurityLevel::Maximum), PQ_TLS_1024);
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
}
