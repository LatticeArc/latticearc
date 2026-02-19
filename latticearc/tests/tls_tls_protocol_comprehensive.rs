#![deny(unsafe_code)]
// Test files use unwrap(), expect(), and panic! for assertions
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::panic)]
// Tests may use wildcard matches for brevity
#![allow(clippy::wildcard_enum_match_arm)]
// Tests use indexing for vector access
#![allow(clippy::indexing_slicing)]

//! Comprehensive TLS Protocol Tests for arc-tls
//!
//! This test suite covers TLS 1.3 handshake, cipher suites, certificates,
//! and error handling scenarios as specified in DETAILED_TASK_LIST.md.
//!
//! Test Categories:
//! 1. TLS Handshake Tests (3.1.1-3.1.5)
//! 2. Cipher Suite Tests (3.1.6-3.1.8)
//! 3. Certificate Tests (3.1.9-3.1.12)
//! 4. Error Handling Tests
//!
//! Run with: cargo test --package arc-tls --test tls_protocol_comprehensive --all-features

use latticearc::tls::basic_features::{get_config_info, load_certs, load_private_key, tls_connect};
use latticearc::tls::error::{
    ErrorCode, ErrorContext, ErrorSeverity, OperationPhase, RecoveryHint,
};
use latticearc::tls::pq_key_exchange::{
    PqKexMode, get_kex_info, get_kex_provider, is_custom_hybrid_available, is_pq_available,
};
use latticearc::tls::recovery::{
    CircuitBreaker, CircuitState, DegradationConfig, FallbackStrategy, RetryPolicy,
};
use latticearc::tls::selector::{
    CLASSICAL_TLS_KEX, CLASSICAL_TLS_SCHEME, DEFAULT_PQ_TLS_KEX, DEFAULT_PQ_TLS_SCHEME,
    DEFAULT_TLS_KEX, DEFAULT_TLS_SCHEME, HYBRID_TLS_512, HYBRID_TLS_768, HYBRID_TLS_1024,
    PQ_TLS_512, PQ_TLS_768, PQ_TLS_1024, TlsConstraints, TlsContext, TlsPolicyEngine, TlsUseCase,
};
use latticearc::tls::session_store::{
    ConfigurableSessionStore, PersistentSessionStore, create_session_store,
};
use latticearc::tls::tls13::{
    HandshakeState, HandshakeStats, Tls13Config, get_cipher_suites, get_secure_cipher_suites,
    validate_cipher_suites, verify_config,
};
use latticearc::tls::{
    ClientAuthConfig, ClientVerificationMode, SessionPersistenceConfig, TlsConfig, TlsError,
    TlsMode, VERSION, pq_enabled,
};
use latticearc::unified_api::{PerformancePreference, SecurityLevel};
use rustls::ProtocolVersion;
use std::io::Write;
use std::sync::Arc;
use std::time::Duration;
use tempfile::NamedTempFile;

// =============================================================================
// SECTION 1: TLS HANDSHAKE TESTS (3.1.1-3.1.5)
// =============================================================================

mod handshake_tests {
    use super::*;

    // -------------------------------------------------------------------------
    // 3.1.1 Post-quantum TLS 1.3 handshake with ML-KEM key exchange
    // -------------------------------------------------------------------------

    #[test]
    fn test_pq_tls13_handshake_config_hybrid_mode() {
        // Verify hybrid mode configuration for PQ TLS 1.3
        let config = Tls13Config::hybrid();
        assert_eq!(config.mode, TlsMode::Hybrid);
        assert!(config.use_pq_kx, "Hybrid mode should enable PQ key exchange");
        assert_eq!(config.protocol_versions, vec![&rustls::version::TLS13]);
    }

    #[test]
    fn test_pq_tls13_handshake_config_pq_only_mode() {
        // Verify PQ-only mode configuration
        let config = Tls13Config::pq();
        assert_eq!(config.mode, TlsMode::Pq);
        assert!(config.use_pq_kx, "PQ mode should enable PQ key exchange");
    }

    #[test]
    fn test_pq_tls13_key_exchange_info_mlkem768() {
        // Verify ML-KEM-768 key exchange information
        let info = get_kex_info(TlsMode::Hybrid, PqKexMode::RustlsPq);
        assert_eq!(info.method, "X25519MLKEM768");
        assert!(info.is_pq_secure);
        assert_eq!(info.pk_size, 32 + 1184); // X25519 + ML-KEM-768 PK
        assert_eq!(info.sk_size, 32 + 2400); // X25519 + ML-KEM-768 SK
        assert_eq!(info.ct_size, 32 + 1088); // X25519 + ML-KEM-768 CT
        assert_eq!(info.ss_size, 64); // 64-byte hybrid shared secret
    }

    #[test]
    fn test_pq_tls13_provider_availability() {
        // Verify PQ provider is available
        assert!(is_pq_available(), "PQ key exchange should be available");

        let provider = get_kex_provider(TlsMode::Hybrid, PqKexMode::RustlsPq);
        assert!(provider.is_ok(), "Should be able to get PQ provider");
    }

    #[test]
    fn test_pq_tls13_handshake_states() {
        // Verify handshake state machine
        let states = [
            HandshakeState::Start,
            HandshakeState::ClientHelloSent,
            HandshakeState::ServerHelloReceived,
            HandshakeState::ServerFinishedReceived,
            HandshakeState::ClientFinishedSent,
            HandshakeState::Complete,
        ];

        // All states should be distinct
        for (i, state1) in states.iter().enumerate() {
            for (j, state2) in states.iter().enumerate() {
                if i != j {
                    assert_ne!(state1, state2, "States at {} and {} should differ", i, j);
                }
            }
        }
    }

    #[test]
    fn test_pq_tls13_handshake_stats_default() {
        let stats = HandshakeStats::default();
        assert_eq!(stats.duration_ms, 0);
        assert_eq!(stats.round_trips, 2); // TLS 1.3 requires 2 round trips
        assert_eq!(stats.kex_time_ms, 0);
        assert_eq!(stats.cert_time_ms, 0);
        assert_eq!(stats.client_hello_size, 0);
        assert_eq!(stats.server_hello_size, 0);
    }

    // -------------------------------------------------------------------------
    // 3.1.2 Certificate chain validation
    // -------------------------------------------------------------------------

    #[test]
    fn test_certificate_chain_validation_no_file() {
        let result = load_certs("nonexistent_cert.pem");
        assert!(result.is_err());

        match result.unwrap_err() {
            TlsError::Certificate { code, .. } => {
                assert_eq!(code, ErrorCode::CertificateParseError);
            }
            _ => panic!("Expected Certificate error"),
        }
    }

    #[test]
    fn test_certificate_chain_validation_invalid_pem() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(temp_file, "INVALID PEM DATA - NOT A CERTIFICATE").unwrap();

        let result = load_certs(temp_file.path().to_str().unwrap());
        assert!(result.is_err());

        match result.unwrap_err() {
            TlsError::Certificate { code, .. } => {
                assert_eq!(code, ErrorCode::CertificateParseError);
            }
            _ => panic!("Expected Certificate error"),
        }
    }

    // -------------------------------------------------------------------------
    // 3.1.3 Session resumption with PQ cipher suites
    // -------------------------------------------------------------------------

    #[test]
    fn test_session_resumption_config_default() {
        let config = TlsConfig::new();
        assert!(config.enable_resumption, "Resumption should be enabled by default");
        assert_eq!(config.session_lifetime, 7200); // 2 hours default
    }

    #[test]
    fn test_session_resumption_config_custom_lifetime() {
        let config = TlsConfig::new().with_session_lifetime(3600);
        assert_eq!(config.session_lifetime, 3600);
    }

    #[test]
    fn test_session_resumption_disabled() {
        let config = TlsConfig::new().with_resumption(false);
        assert!(!config.enable_resumption);
    }

    #[test]
    fn test_session_store_creation() {
        let store = create_session_store(None);
        assert_eq!(Arc::strong_count(&store), 1);
    }

    #[test]
    fn test_session_store_with_persistence_config() {
        let config = SessionPersistenceConfig::new(std::env::temp_dir().join("sessions.bin"), 500);
        let store = create_session_store(Some(&config));
        assert_eq!(Arc::strong_count(&store), 1);
    }

    #[test]
    fn test_configurable_session_store() {
        let store = ConfigurableSessionStore::new(100);
        assert_eq!(store.capacity(), 100);
    }

    #[test]
    fn test_persistent_session_store() {
        let store = PersistentSessionStore::new(std::env::temp_dir().join("test.bin"), 200);
        assert_eq!(store.capacity(), 200);
        assert!(!store.is_persistence_enabled()); // Not yet supported by rustls
    }

    // -------------------------------------------------------------------------
    // 3.1.4 Client authentication flow
    // -------------------------------------------------------------------------

    #[test]
    fn test_client_auth_config_creation() {
        let auth_config = ClientAuthConfig::new("client.crt", "client.key");
        assert_eq!(auth_config.cert_path, "client.crt");
        assert_eq!(auth_config.key_path, "client.key");
    }

    #[test]
    fn test_client_verification_mode_none() {
        let mode = ClientVerificationMode::None;
        assert_eq!(mode, ClientVerificationMode::default());
    }

    #[test]
    fn test_client_verification_mode_optional() {
        let config = TlsConfig::new().with_client_verification(ClientVerificationMode::Optional);
        assert_eq!(config.client_verification, ClientVerificationMode::Optional);
    }

    #[test]
    fn test_client_verification_mode_required() {
        let config = TlsConfig::new().with_client_verification(ClientVerificationMode::Required);
        assert_eq!(config.client_verification, ClientVerificationMode::Required);
    }

    #[test]
    fn test_mtls_client_auth_config() {
        let config = TlsConfig::new().with_client_auth("client.crt", "client.key");
        assert!(config.client_auth.is_some());
        let auth = config.client_auth.unwrap();
        assert_eq!(auth.cert_path, "client.crt");
        assert_eq!(auth.key_path, "client.key");
    }

    #[test]
    fn test_mtls_server_ca_certs_config() {
        let config = TlsConfig::new()
            .with_client_verification(ClientVerificationMode::Required)
            .with_client_ca_certs("ca-bundle.crt");
        assert_eq!(config.client_ca_certs, Some("ca-bundle.crt".to_string()));
    }

    // -------------------------------------------------------------------------
    // 3.1.5 Handshake failure scenarios (timeout, protocol mismatch)
    // -------------------------------------------------------------------------

    #[tokio::test]
    async fn test_handshake_failure_invalid_domain() {
        let config = TlsConfig::default();
        let result = tls_connect(
            "invalid.nonexistent.domain.test:443",
            "invalid.nonexistent.domain.test",
            &config,
        )
        .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_handshake_failure_empty_domain_name() {
        let config = TlsConfig::default();
        let result = tls_connect("example.com:443", "", &config).await;

        assert!(result.is_err());
        match result.unwrap_err() {
            TlsError::Config { code, .. } => {
                assert_eq!(code, ErrorCode::InvalidConfig);
            }
            _ => panic!("Expected Config error for empty domain"),
        }
    }

    #[test]
    fn test_handshake_failure_invalid_protocol_version_range() {
        // Test configuration with invalid protocol version range
        let config = TlsConfig::new()
            .with_min_protocol_version(ProtocolVersion::TLSv1_3)
            .with_max_protocol_version(ProtocolVersion::TLSv1_2); // max < min

        let result = config.validate();
        assert!(result.is_err());

        match result.unwrap_err() {
            TlsError::Config { code, field, .. } => {
                assert_eq!(code, ErrorCode::InvalidProtocolVersion);
                assert_eq!(field, Some("protocol_version".to_string()));
            }
            _ => panic!("Expected Config error for invalid protocol versions"),
        }
    }

    #[test]
    fn test_handshake_early_data_validation() {
        // Early data enabled but size is 0 should fail
        let config = Tls13Config::hybrid().with_early_data(0);
        let result = verify_config(&config);
        assert!(result.is_err());
    }

    #[test]
    fn test_handshake_early_data_valid() {
        let config = Tls13Config::hybrid().with_early_data(4096);
        let result = verify_config(&config);
        assert!(result.is_ok());
    }
}

// =============================================================================
// SECTION 2: CIPHER SUITE TESTS (3.1.6-3.1.8)
// =============================================================================

mod cipher_suite_tests {
    use super::*;

    // -------------------------------------------------------------------------
    // 3.1.6 TLS_AES_256_GCM_SHA384 with ML-KEM
    // -------------------------------------------------------------------------

    #[test]
    fn test_cipher_suite_aes_256_gcm_sha384_classic() {
        let suites = get_cipher_suites(TlsMode::Classic);
        assert!(!suites.is_empty());
        assert_eq!(suites.len(), 3);

        // First suite should be AES-256-GCM (strongest)
        let first_suite = &suites[0];
        assert!(format!("{:?}", first_suite).contains("AES_256_GCM"));
    }

    #[test]
    fn test_cipher_suite_aes_256_gcm_sha384_hybrid() {
        let suites = get_cipher_suites(TlsMode::Hybrid);
        assert!(!suites.is_empty());
        assert_eq!(suites.len(), 3);

        // Verify AES-256-GCM is available for hybrid mode
        let has_aes256 = suites.iter().any(|s| format!("{:?}", s).contains("AES_256_GCM"));
        assert!(has_aes256, "Hybrid mode should include AES-256-GCM");
    }

    // -------------------------------------------------------------------------
    // 3.1.7 TLS_CHACHA20_POLY1305_SHA256 with ML-KEM
    // -------------------------------------------------------------------------

    #[test]
    fn test_cipher_suite_chacha20_poly1305_classic() {
        let suites = get_cipher_suites(TlsMode::Classic);

        let has_chacha = suites.iter().any(|s| format!("{:?}", s).contains("CHACHA20_POLY1305"));
        assert!(has_chacha, "Classic mode should include ChaCha20-Poly1305");
    }

    #[test]
    fn test_cipher_suite_chacha20_poly1305_hybrid() {
        let suites = get_cipher_suites(TlsMode::Hybrid);

        let has_chacha = suites.iter().any(|s| format!("{:?}", s).contains("CHACHA20_POLY1305"));
        assert!(has_chacha, "Hybrid mode should include ChaCha20-Poly1305");
    }

    #[test]
    fn test_cipher_suite_chacha20_poly1305_pq() {
        let suites = get_cipher_suites(TlsMode::Pq);
        assert_eq!(suites.len(), 2);

        let has_chacha = suites.iter().any(|s| format!("{:?}", s).contains("CHACHA20_POLY1305"));
        assert!(has_chacha, "PQ mode should include ChaCha20-Poly1305");
    }

    // -------------------------------------------------------------------------
    // 3.1.8 Hybrid cipher suite negotiation (classical + PQ)
    // -------------------------------------------------------------------------

    #[test]
    fn test_hybrid_cipher_suite_negotiation_scheme_512() {
        assert_eq!(HYBRID_TLS_512, "hybrid-x25519-ml-kem-512");
    }

    #[test]
    fn test_hybrid_cipher_suite_negotiation_scheme_768() {
        assert_eq!(HYBRID_TLS_768, "hybrid-x25519-ml-kem-768");
    }

    #[test]
    fn test_hybrid_cipher_suite_negotiation_scheme_1024() {
        assert_eq!(HYBRID_TLS_1024, "hybrid-x25519-ml-kem-1024");
    }

    #[test]
    fn test_hybrid_cipher_suite_default_scheme() {
        assert_eq!(DEFAULT_TLS_SCHEME, "hybrid-x25519-ml-kem-768");
        assert_eq!(DEFAULT_TLS_KEX, "X25519MLKEM768");
    }

    #[test]
    fn test_pq_only_cipher_suite_schemes() {
        assert_eq!(PQ_TLS_512, "pq-ml-kem-512");
        assert_eq!(PQ_TLS_768, "pq-ml-kem-768");
        assert_eq!(PQ_TLS_1024, "pq-ml-kem-1024");
        assert_eq!(DEFAULT_PQ_TLS_KEX, "MLKEM768");
        assert_eq!(DEFAULT_PQ_TLS_SCHEME, "pq-ml-kem-768");
    }

    #[test]
    fn test_classical_cipher_suite_scheme() {
        assert_eq!(CLASSICAL_TLS_KEX, "X25519");
        assert_eq!(CLASSICAL_TLS_SCHEME, "classic-x25519");
    }

    #[test]
    fn test_secure_cipher_suites_validation() {
        let secure_suites = get_secure_cipher_suites();
        assert_eq!(secure_suites.len(), 3);

        // All secure suites should pass validation
        let result = validate_cipher_suites(&secure_suites);
        assert!(result.is_ok());
    }

    #[test]
    fn test_cipher_suite_selection_by_security_level() {
        // Standard -> ML-KEM-512
        assert_eq!(TlsPolicyEngine::select_hybrid_scheme(SecurityLevel::Standard), HYBRID_TLS_512);

        // High -> ML-KEM-768
        assert_eq!(TlsPolicyEngine::select_hybrid_scheme(SecurityLevel::High), HYBRID_TLS_768);

        // Maximum -> ML-KEM-1024
        assert_eq!(TlsPolicyEngine::select_hybrid_scheme(SecurityLevel::Maximum), HYBRID_TLS_1024);
    }

    #[test]
    fn test_kex_algorithm_selection() {
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

// =============================================================================
// SECTION 3: CERTIFICATE TESTS (3.1.9-3.1.12)
// =============================================================================

mod certificate_tests {
    use super::*;

    // -------------------------------------------------------------------------
    // 3.1.9 ML-DSA signed certificates (Configuration tests)
    // -------------------------------------------------------------------------

    #[test]
    fn test_ml_dsa_certificate_config_pq_mode() {
        // Test that PQ mode is properly configured for ML-DSA certificates
        let config = TlsConfig::new().security_level(SecurityLevel::Quantum);
        assert_eq!(config.mode, TlsMode::Pq);
    }

    #[test]
    fn test_ml_dsa_certificate_use_case_government() {
        // Government use case should use PQ for ML-DSA certificate support
        let mode = TlsPolicyEngine::recommend_mode(TlsUseCase::Government);
        assert_eq!(mode, TlsMode::Pq);
    }

    // -------------------------------------------------------------------------
    // 3.1.10 Certificate chain with PQ algorithms
    // -------------------------------------------------------------------------

    #[test]
    fn test_certificate_chain_pq_config() {
        let config = Tls13Config::pq();
        assert!(config.use_pq_kx);
        assert_eq!(config.mode, TlsMode::Pq);
    }

    #[test]
    fn test_certificate_chain_hybrid_config() {
        let config = Tls13Config::hybrid();
        assert!(config.use_pq_kx);
        assert_eq!(config.mode, TlsMode::Hybrid);
    }

    // -------------------------------------------------------------------------
    // 3.1.11 Self-signed certificate handling
    // -------------------------------------------------------------------------

    #[test]
    fn test_self_signed_cert_error_code() {
        // Verify self-signed certificate error code exists
        let code = ErrorCode::CertificateSelfSigned;
        assert_eq!(format!("{}", code), "CERTIFICATE_SELF_SIGNED");
    }

    #[test]
    fn test_certificate_error_codes() {
        // Verify all certificate-related error codes
        assert_eq!(format!("{}", ErrorCode::CertificateParseError), "CERTIFICATE_PARSE_ERROR");
        assert_eq!(format!("{}", ErrorCode::CertificateExpired), "CERTIFICATE_EXPIRED");
        assert_eq!(format!("{}", ErrorCode::CertificateNotYetValid), "CERTIFICATE_NOT_YET_VALID");
        assert_eq!(format!("{}", ErrorCode::CertificateRevoked), "CERTIFICATE_REVOKED");
        assert_eq!(format!("{}", ErrorCode::CertificateInvalid), "CERTIFICATE_INVALID");
        assert_eq!(
            format!("{}", ErrorCode::CertificateChainIncomplete),
            "CERTIFICATE_CHAIN_INCOMPLETE"
        );
        assert_eq!(
            format!("{}", ErrorCode::CertificateHostnameMismatch),
            "CERTIFICATE_HOSTNAME_MISMATCH"
        );
    }

    // -------------------------------------------------------------------------
    // 3.1.12 Certificate revocation checking
    // -------------------------------------------------------------------------

    #[test]
    fn test_certificate_revoked_error_code() {
        let code = ErrorCode::CertificateRevoked;
        assert_eq!(format!("{}", code), "CERTIFICATE_REVOKED");
    }

    #[test]
    fn test_certificate_signature_invalid_error() {
        let code = ErrorCode::CertificateSignatureInvalid;
        assert_eq!(format!("{}", code), "CERTIFICATE_SIGNATURE_INVALID");
    }

    #[test]
    fn test_certificate_not_valid_for_purpose_error() {
        let code = ErrorCode::CertificateNotValidForPurpose;
        assert_eq!(format!("{}", code), "CERTIFICATE_NOT_VALID_FOR_PURPOSE");
    }

    #[test]
    fn test_certificate_bad_der_errors() {
        assert_eq!(format!("{}", ErrorCode::CertificateBadDer), "CERTIFICATE_BAD_DER");
        assert_eq!(
            format!("{}", ErrorCode::CertificateBadDerSequence),
            "CERTIFICATE_BAD_DER_SEQUENCE"
        );
        assert_eq!(format!("{}", ErrorCode::CertificateBadDerTime), "CERTIFICATE_BAD_DER_TIME");
    }
}

// =============================================================================
// SECTION 4: ERROR HANDLING TESTS
// =============================================================================

mod error_handling_tests {
    use super::*;

    // -------------------------------------------------------------------------
    // Invalid certificate rejection
    // -------------------------------------------------------------------------

    #[test]
    fn test_invalid_certificate_rejection_missing_file() {
        let result = load_certs("missing_certificate.pem");
        assert!(result.is_err());

        let err = result.unwrap_err();
        assert_eq!(err.code(), ErrorCode::CertificateParseError);
        assert!(err.is_recoverable());
    }

    #[test]
    fn test_invalid_private_key_rejection_missing_file() {
        let result = load_private_key("missing_key.pem");
        assert!(result.is_err());

        let err = result.unwrap_err();
        assert_eq!(err.code(), ErrorCode::MissingPrivateKey);
    }

    #[test]
    fn test_invalid_private_key_rejection_invalid_pem() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(temp_file, "NOT A VALID PRIVATE KEY").unwrap();

        let result = load_private_key(temp_file.path().to_str().unwrap());
        assert!(result.is_err());

        match result.unwrap_err() {
            TlsError::Certificate { code, .. } => {
                assert_eq!(code, ErrorCode::MissingPrivateKey);
            }
            _ => panic!("Expected Certificate error for invalid key"),
        }
    }

    // -------------------------------------------------------------------------
    // Expired certificate handling
    // -------------------------------------------------------------------------

    #[test]
    fn test_expired_certificate_error_code() {
        let code = ErrorCode::CertificateExpired;
        assert_eq!(format!("{}", code), "CERTIFICATE_EXPIRED");
    }

    #[test]
    fn test_certificate_not_yet_valid_error_code() {
        let code = ErrorCode::CertificateNotYetValid;
        assert_eq!(format!("{}", code), "CERTIFICATE_NOT_YET_VALID");
    }

    // -------------------------------------------------------------------------
    // Signature verification failures
    // -------------------------------------------------------------------------

    #[test]
    fn test_signature_verification_failed_error() {
        let code = ErrorCode::SignatureVerificationFailed;
        assert_eq!(format!("{}", code), "SIGNATURE_VERIFICATION_FAILED");
    }

    #[test]
    fn test_certificate_signature_invalid_recovery() {
        // Create error context for signature verification
        let context = ErrorContext {
            code: ErrorCode::CertificateSignatureInvalid,
            severity: ErrorSeverity::Error,
            phase: OperationPhase::CertificateVerification,
            ..ErrorContext::default()
        };

        assert_eq!(context.code, ErrorCode::CertificateSignatureInvalid);
        assert_eq!(context.severity, ErrorSeverity::Error);
        assert_eq!(context.phase, OperationPhase::CertificateVerification);
    }

    // -------------------------------------------------------------------------
    // Key exchange failures
    // -------------------------------------------------------------------------

    #[test]
    fn test_key_exchange_failed_error() {
        let code = ErrorCode::KeyExchangeFailed;
        assert_eq!(format!("{}", code), "KEY_EXCHANGE_FAILED");
    }

    #[test]
    fn test_encapsulation_failed_error() {
        let code = ErrorCode::EncapsulationFailed;
        assert_eq!(format!("{}", code), "ENCAPSULATION_FAILED");
    }

    #[test]
    fn test_decapsulation_failed_error() {
        let code = ErrorCode::DecapsulationFailed;
        assert_eq!(format!("{}", code), "DECAPSULATION_FAILED");
    }

    #[test]
    fn test_hybrid_kem_failed_error() {
        let code = ErrorCode::HybridKemFailed;
        assert_eq!(format!("{}", code), "HYBRID_KEM_FAILED");
    }

    #[test]
    fn test_pq_not_available_error() {
        let code = ErrorCode::PqNotAvailable;
        assert_eq!(format!("{}", code), "PQ_NOT_AVAILABLE");
    }

    // -------------------------------------------------------------------------
    // Error severity and recovery
    // -------------------------------------------------------------------------

    #[test]
    fn test_error_severity_ordering() {
        assert!(ErrorSeverity::Info < ErrorSeverity::Warning);
        assert!(ErrorSeverity::Warning < ErrorSeverity::Error);
        assert!(ErrorSeverity::Error < ErrorSeverity::Critical);
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
        let hint = RecoveryHint::Fallback { description: "Fall back to classical TLS".to_string() };
        match hint {
            RecoveryHint::Fallback { description } => {
                assert!(description.contains("classical"));
            }
            _ => panic!("Expected Fallback hint"),
        }
    }

    #[test]
    fn test_recovery_hint_reconfigure() {
        let hint = RecoveryHint::Reconfigure {
            field: "cipher_suites".to_string(),
            suggestion: "Use TLS 1.3 cipher suites".to_string(),
        };
        match hint {
            RecoveryHint::Reconfigure { field, suggestion } => {
                assert_eq!(field, "cipher_suites");
                assert!(suggestion.contains("TLS 1.3"));
            }
            _ => panic!("Expected Reconfigure hint"),
        }
    }

    // -------------------------------------------------------------------------
    // Retry policy tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_retry_policy_default() {
        let policy = RetryPolicy::default();
        assert_eq!(policy.max_attempts, 3);
        assert_eq!(policy.initial_backoff, Duration::from_millis(100));
        assert_eq!(policy.max_backoff, Duration::from_secs(5));
        assert!(policy.jitter);
    }

    #[test]
    fn test_retry_policy_conservative() {
        let policy = RetryPolicy::conservative();
        assert_eq!(policy.max_attempts, 2);
    }

    #[test]
    fn test_retry_policy_aggressive() {
        let policy = RetryPolicy::aggressive();
        assert_eq!(policy.max_attempts, 5);
    }

    #[test]
    fn test_retry_policy_backoff_exponential() {
        let policy = RetryPolicy::default();
        let backoff1 = policy.backoff_for_attempt(1);
        let backoff2 = policy.backoff_for_attempt(2);

        // Second attempt should have longer backoff
        assert!(backoff2 > backoff1);
    }

    // -------------------------------------------------------------------------
    // Circuit breaker tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_circuit_breaker_initial_state() {
        let breaker = CircuitBreaker::new(3, Duration::from_secs(60));
        assert_eq!(breaker.state(), CircuitState::Closed);
    }

    #[test]
    fn test_circuit_breaker_opens_after_threshold() {
        let breaker = CircuitBreaker::new(3, Duration::from_secs(60));

        breaker.record_failure();
        breaker.record_failure();
        breaker.record_failure();

        assert_eq!(breaker.state(), CircuitState::Open);
    }

    #[test]
    fn test_circuit_breaker_reset() {
        let breaker = CircuitBreaker::new(3, Duration::from_secs(60));

        breaker.record_failure();
        breaker.record_failure();
        breaker.record_failure();
        assert_eq!(breaker.state(), CircuitState::Open);

        breaker.reset();
        assert_eq!(breaker.state(), CircuitState::Closed);
    }

    #[test]
    fn test_circuit_breaker_success_resets_failures() {
        let breaker = CircuitBreaker::new(5, Duration::from_secs(60));

        breaker.record_failure();
        breaker.record_failure();
        breaker.record_success(); // Should reset failure count

        assert_eq!(breaker.state(), CircuitState::Closed);
    }

    // -------------------------------------------------------------------------
    // Fallback strategy tests
    // -------------------------------------------------------------------------

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

    // -------------------------------------------------------------------------
    // Degradation config tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_degradation_config_default() {
        let config = DegradationConfig::default();
        assert!(config.enable_fallback);
        assert!(!config.allow_reduced_security);
        assert_eq!(config.max_degradation_attempts, 2);
    }
}

// =============================================================================
// SECTION 5: TLS MODE AND POLICY ENGINE TESTS
// =============================================================================

mod tls_mode_tests {
    use super::*;

    #[test]
    fn test_tls_mode_default_is_hybrid() {
        assert_eq!(TlsMode::default(), TlsMode::Hybrid);
    }

    #[test]
    fn test_tls_config_new_default() {
        let config = TlsConfig::new();
        assert_eq!(config.mode, TlsMode::Hybrid);
        assert!(config.enable_fallback);
        assert!(config.enable_resumption);
    }

    #[test]
    fn test_tls_config_use_case_webserver() {
        let config = TlsConfig::new().use_case(TlsUseCase::WebServer);
        assert_eq!(config.mode, TlsMode::Hybrid);
    }

    #[test]
    fn test_tls_config_use_case_iot() {
        let config = TlsConfig::new().use_case(TlsUseCase::IoT);
        assert_eq!(config.mode, TlsMode::Classic);
    }

    #[test]
    fn test_tls_config_use_case_government() {
        let config = TlsConfig::new().use_case(TlsUseCase::Government);
        assert_eq!(config.mode, TlsMode::Pq);
    }

    #[test]
    fn test_tls_config_security_level_quantum() {
        let config = TlsConfig::new().security_level(SecurityLevel::Quantum);
        assert_eq!(config.mode, TlsMode::Pq);
    }

    #[test]
    fn test_tls_config_security_level_maximum() {
        let config = TlsConfig::new().security_level(SecurityLevel::Maximum);
        assert_eq!(config.mode, TlsMode::Hybrid); // Maximum uses Hybrid for defense-in-depth
    }

    #[test]
    fn test_tls_use_case_all() {
        let all = TlsUseCase::all();
        assert_eq!(all.len(), 10);
    }

    #[test]
    fn test_tls_use_case_descriptions() {
        assert!(!TlsUseCase::WebServer.description().is_empty());
        assert!(!TlsUseCase::FinancialServices.description().is_empty());
        assert!(!TlsUseCase::Government.description().is_empty());
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
    fn test_tls_context_default() {
        let ctx = TlsContext::default();
        assert_eq!(ctx.security_level, SecurityLevel::High);
        assert_eq!(ctx.performance_preference, PerformancePreference::Balanced);
        assert!(ctx.pq_available);
    }

    #[test]
    fn test_tls_context_with_use_case() {
        let ctx = TlsContext::with_use_case(TlsUseCase::FinancialServices);
        assert_eq!(ctx.use_case, Some(TlsUseCase::FinancialServices));
    }

    #[test]
    fn test_policy_engine_create_config() {
        let ctx = TlsContext::with_use_case(TlsUseCase::WebServer);
        let config = TlsPolicyEngine::create_config(&ctx);
        assert_eq!(config.mode, TlsMode::Hybrid);
    }

    #[test]
    fn test_policy_engine_select_balanced() {
        // Quantum always uses PQ-only
        assert_eq!(
            TlsPolicyEngine::select_balanced(SecurityLevel::Quantum, PerformancePreference::Speed),
            TlsMode::Pq
        );

        // Standard uses Hybrid
        assert_eq!(
            TlsPolicyEngine::select_balanced(
                SecurityLevel::Standard,
                PerformancePreference::Balanced
            ),
            TlsMode::Hybrid
        );
    }
}

// =============================================================================
// SECTION 6: CONFIGURATION BUILDER TESTS
// =============================================================================

mod config_builder_tests {
    use super::*;

    #[test]
    fn test_config_builder_chain() {
        let config = TlsConfig::new()
            .use_case(TlsUseCase::FinancialServices)
            .with_tracing()
            .with_fallback(true)
            .with_resumption(true)
            .with_session_lifetime(3600);

        assert_eq!(config.mode, TlsMode::Hybrid);
        assert!(config.enable_tracing);
        assert!(config.enable_fallback);
        assert!(config.enable_resumption);
        assert_eq!(config.session_lifetime, 3600);
    }

    #[test]
    fn test_config_builder_alpn_protocols() {
        let config = TlsConfig::new().with_alpn_protocols(vec!["h2", "http/1.1"]);

        assert_eq!(config.alpn_protocols.len(), 2);
        assert_eq!(config.alpn_protocols[0], b"h2");
        assert_eq!(config.alpn_protocols[1], b"http/1.1");
    }

    #[test]
    fn test_config_builder_max_fragment_size() {
        let config = TlsConfig::new().with_max_fragment_size(4096);

        assert_eq!(config.max_fragment_size, Some(4096));
    }

    #[test]
    fn test_config_builder_early_data() {
        let config = TlsConfig::new().with_early_data(8192);

        assert!(config.enable_early_data);
        assert_eq!(config.max_early_data_size, 8192);
    }

    #[test]
    fn test_config_builder_retry_policy() {
        let policy = RetryPolicy::conservative();
        let config = TlsConfig::new().with_retry_policy(policy);

        assert!(config.retry_policy.is_some());
    }

    #[test]
    fn test_config_builder_key_logging() {
        let config = TlsConfig::new().with_key_logging();

        assert!(config.enable_key_logging);
    }

    #[test]
    fn test_config_builder_protocol_versions() {
        let config = TlsConfig::new()
            .with_min_protocol_version(ProtocolVersion::TLSv1_3)
            .with_max_protocol_version(ProtocolVersion::TLSv1_3);

        assert_eq!(config.min_protocol_version, Some(ProtocolVersion::TLSv1_3));
        assert_eq!(config.max_protocol_version, Some(ProtocolVersion::TLSv1_3));
    }

    #[test]
    fn test_tls13_config_builder_chain() {
        let config = Tls13Config::hybrid()
            .with_early_data(4096)
            .with_pq_kx(true)
            .with_alpn_protocols(vec!["h2"])
            .with_max_fragment_size(8192);

        assert!(config.enable_early_data);
        assert_eq!(config.max_early_data_size, 4096);
        assert!(config.use_pq_kx);
        assert_eq!(config.alpn_protocols.len(), 1);
        assert_eq!(config.max_fragment_size, Some(8192));
    }

    #[test]
    fn test_tls13_config_from_tls_config() {
        let tls_config = TlsConfig::new();
        let tls13_config = Tls13Config::from(&tls_config);

        assert_eq!(tls13_config.mode, TlsMode::Hybrid);
    }

    #[test]
    fn test_config_validation_success() {
        let config = TlsConfig::new();
        assert!(config.validate().is_ok());
    }
}

// =============================================================================
// SECTION 7: VERSION AND FEATURE TESTS
// =============================================================================

mod version_feature_tests {
    use super::*;

    #[test]
    fn test_version_not_empty() {
        assert!(!VERSION.is_empty());
    }

    #[test]
    fn test_pq_enabled() {
        assert!(pq_enabled());
    }

    #[test]
    fn test_custom_hybrid_available() {
        assert!(is_custom_hybrid_available());
    }

    #[test]
    fn test_pq_available() {
        assert!(is_pq_available());
    }

    #[test]
    fn test_config_info_classic() {
        let config = TlsConfig::new().use_case(TlsUseCase::IoT);
        let info = get_config_info(&config);
        assert!(info.contains("Classic"));
        assert!(info.contains("Not PQ"));
    }

    #[test]
    fn test_config_info_hybrid() {
        let config = TlsConfig::new();
        let info = get_config_info(&config);
        assert!(info.contains("Hybrid"));
        assert!(info.contains("PQ secure"));
    }

    #[test]
    fn test_config_info_pq() {
        let config = TlsConfig::new().security_level(SecurityLevel::Quantum);
        let info = get_config_info(&config);
        assert!(info.contains("Post-quantum") || info.contains("PQ"));
    }
}

// =============================================================================
// SECTION 8: KEY EXCHANGE INFORMATION TESTS
// =============================================================================

mod kex_info_tests {
    use super::*;

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
    fn test_kex_info_hybrid_rustls_pq() {
        let info = get_kex_info(TlsMode::Hybrid, PqKexMode::RustlsPq);
        assert_eq!(info.method, "X25519MLKEM768");
        assert!(info.is_pq_secure);
        assert_eq!(info.ss_size, 64);
    }

    #[test]
    fn test_kex_info_custom_hybrid() {
        let info = get_kex_info(TlsMode::Hybrid, PqKexMode::CustomHybrid);
        assert!(info.method.contains("Custom Hybrid"));
        assert!(info.is_pq_secure);
        assert_eq!(info.ss_size, 64);
    }

    #[test]
    fn test_kex_provider_classical() {
        let provider = get_kex_provider(TlsMode::Classic, PqKexMode::Classical);
        assert!(provider.is_ok());
    }

    #[test]
    fn test_kex_provider_hybrid() {
        let provider = get_kex_provider(TlsMode::Hybrid, PqKexMode::RustlsPq);
        assert!(provider.is_ok());
    }

    #[test]
    fn test_kex_provider_pq() {
        let provider = get_kex_provider(TlsMode::Pq, PqKexMode::RustlsPq);
        assert!(provider.is_ok());
    }
}

// =============================================================================
// SECTION 9: NETWORK INTEGRATION TESTS
// =============================================================================
// Real TLS handshake tests (classic, hybrid, PQ, mTLS, ALPN, large data) are in
// arc-tls/tests/tls_handshake_roundtrip.rs — they use rcgen-generated certs and
// localhost TCP, no external dependencies.
