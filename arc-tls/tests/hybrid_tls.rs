#![deny(unsafe_code)]
// Test files use unwrap() for simplicity
#![allow(clippy::unwrap_used)]
// Explicit bool comparisons can be clearer in tests
#![allow(clippy::bool_assert_comparison)]
// Test files use indexing for vector access
#![allow(clippy::indexing_slicing)]
// vec![] used for test data construction
#![allow(clippy::useless_vec)]

//! Tests for hybrid TLS 1.3 implementation

use arc_tls::*;

#[test]
fn test_tls_modes() {
    use arc_core::SecurityLevel;

    // Test default mode
    let config = TlsConfig::new();
    assert_eq!(config.mode, TlsMode::Hybrid);

    // Test Standard mode (still uses Hybrid - all non-Quantum levels use Hybrid)
    let standard = TlsConfig::new().security_level(SecurityLevel::Standard);
    assert_eq!(standard.mode, TlsMode::Hybrid);

    // Test hybrid mode (default)
    let hybrid = TlsConfig::new();
    assert_eq!(hybrid.mode, TlsMode::Hybrid);

    // Test Maximum still uses Hybrid (only Quantum uses PQ-only)
    let maximum = TlsConfig::new().security_level(SecurityLevel::Maximum);
    assert_eq!(maximum.mode, TlsMode::Hybrid);

    // Test PQ mode via Quantum security level
    let pq = TlsConfig::new().security_level(SecurityLevel::Quantum);
    assert_eq!(pq.mode, TlsMode::Pq);
}

#[test]
fn test_tls13_config_default() {
    let config = Tls13Config::default();
    assert_eq!(config.mode, TlsMode::Hybrid);
    assert!(config.use_pq_kx);
    assert!(!config.enable_early_data);
}

#[test]
fn test_tls13_config_variants() {
    let classic = Tls13Config::classic();
    assert_eq!(classic.mode, TlsMode::Classic);
    assert!(!classic.use_pq_kx);

    let hybrid = Tls13Config::hybrid();
    assert_eq!(hybrid.mode, TlsMode::Hybrid);
    assert!(hybrid.use_pq_kx);

    let pq = Tls13Config::pq();
    assert_eq!(pq.mode, TlsMode::Pq);
    assert!(pq.use_pq_kx);
}

#[test]
fn test_early_data_config() {
    let config = Tls13Config::hybrid().with_early_data(4096);
    assert!(config.enable_early_data);
    assert_eq!(config.max_early_data_size, 4096);
}

#[test]
fn test_handshake_state_transitions() {
    let states = vec![
        HandshakeState::Start,
        HandshakeState::ClientHelloSent,
        HandshakeState::ServerHelloReceived,
        HandshakeState::ServerFinishedReceived,
        HandshakeState::ClientFinishedSent,
        HandshakeState::Complete,
    ];

    // Verify all states are distinct
    for (i, state1) in states.iter().enumerate() {
        for (j, state2) in states.iter().enumerate() {
            if i != j {
                assert_ne!(state1, state2, "States at index {} and {} should be different", i, j);
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
fn test_get_cipher_suites() {
    let classic_suites = get_cipher_suites(TlsMode::Classic);
    assert!(!classic_suites.is_empty());
    assert_eq!(classic_suites.len(), 3);

    let hybrid_suites = get_cipher_suites(TlsMode::Hybrid);
    assert!(!hybrid_suites.is_empty());
    assert_eq!(hybrid_suites.len(), 3);

    let pq_suites = get_cipher_suites(TlsMode::Pq);
    assert!(!pq_suites.is_empty());
    assert_eq!(pq_suites.len(), 2);
}

#[test]
fn test_verify_config() {
    // Valid configurations
    assert!(verify_config(&Tls13Config::classic()).is_ok());
    assert!(verify_config(&Tls13Config::hybrid()).is_ok());
    assert!(verify_config(&Tls13Config::pq()).is_ok());

    // Invalid: early data enabled but size is 0
    let invalid_config = Tls13Config::hybrid().with_early_data(0);
    assert!(verify_config(&invalid_config).is_err());

    // Valid: early data enabled with size set
    let valid_early_data = Tls13Config::hybrid().with_early_data(4096);
    assert!(verify_config(&valid_early_data).is_ok());
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
fn test_config_info() {
    use arc_core::SecurityLevel;

    // Standard uses Hybrid mode (all non-Quantum levels use Hybrid)
    let standard = TlsConfig::new().security_level(SecurityLevel::Standard);
    let info = get_config_info(&standard);
    assert!(info.contains("Hybrid"));

    let hybrid = TlsConfig::new();
    let info = get_config_info(&hybrid);
    assert!(info.contains("Hybrid"));

    let pq = TlsConfig::new().security_level(SecurityLevel::Maximum);
    let info = get_config_info(&pq);
    assert!(info.contains("Hybrid"));

    // Quantum uses PQ-only mode
    let quantum = TlsConfig::new().security_level(SecurityLevel::Quantum);
    let info = get_config_info(&quantum);
    assert!(info.contains("Post-quantum") || info.contains("PQ"));
}

#[test]
fn test_version() {
    assert!(!VERSION.is_empty());
}

#[test]
fn test_tls13_config_from_tls_config() {
    use arc_core::SecurityLevel;

    let configs = vec![
        TlsConfig::new().security_level(SecurityLevel::Standard),
        TlsConfig::new(),
        TlsConfig::new().security_level(SecurityLevel::Maximum),
        TlsConfig::new().security_level(SecurityLevel::Quantum),
    ];

    for config in configs {
        let tls13_config = Tls13Config::from(&config);
        assert_eq!(tls13_config.mode, config.mode);
    }
}

#[test]
fn test_kex_info_hybrid() {
    // Test hybrid mode key exchange info
    let info = get_kex_info(TlsMode::Hybrid, PqKexMode::RustlsPq);
    assert_eq!(info.method, "X25519MLKEM768");
    assert!(info.is_pq_secure);
    assert_eq!(info.pk_size, 1216); // 32 + 1184
    assert_eq!(info.sk_size, 2432); // 32 + 2400
    assert_eq!(info.ct_size, 1120); // 32 + 1088
    assert_eq!(info.ss_size, 64);
}

#[test]
fn test_pq_availability() {
    // PQ is always available via rustls-post-quantum
    let available = is_pq_available();
    assert!(available);
}

#[test]
fn test_custom_hybrid_availability() {
    // Custom hybrid is always available
    let available = is_custom_hybrid_available();
    assert!(available);
}

#[test]
fn test_get_kex_provider_hybrid() {
    let provider = get_kex_provider(TlsMode::Hybrid, PqKexMode::RustlsPq);
    assert!(provider.is_ok());
}

#[test]
fn test_get_kex_provider_classical() {
    let provider = get_kex_provider(TlsMode::Classic, PqKexMode::Classical);
    assert!(provider.is_ok());
}
