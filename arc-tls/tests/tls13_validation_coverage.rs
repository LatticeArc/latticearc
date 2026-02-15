//! Coverage tests for arc-tls/src/tls13.rs uncovered validation paths
//! Targets: validate_cipher_suites error path, verify_config error path

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::field_reassign_with_default
)]

use arc_tls::TlsMode;
use arc_tls::tls13::{
    Tls13Config, get_cipher_suites, get_secure_cipher_suites, validate_cipher_suites, verify_config,
};

#[test]
fn test_validate_cipher_suites_all_valid() {
    let suites = get_secure_cipher_suites();
    let result = validate_cipher_suites(&suites);
    assert!(result.is_ok());
}

#[test]
fn test_validate_cipher_suites_each_mode() {
    for mode in [TlsMode::Classic, TlsMode::Hybrid, TlsMode::Pq] {
        let suites = get_cipher_suites(mode);
        let result = validate_cipher_suites(&suites);
        assert!(result.is_ok(), "Cipher suites for {:?} should be valid", mode);
    }
}

#[test]
fn test_validate_cipher_suites_empty() {
    let result = validate_cipher_suites(&[]);
    assert!(result.is_ok(), "Empty cipher suite list should be valid");
}

#[test]
fn test_verify_config_default_valid() {
    let config = Tls13Config::default();
    let result = verify_config(&config);
    assert!(result.is_ok());
}

#[test]
fn test_verify_config_early_data_zero_size() {
    let mut config = Tls13Config::default();
    config.enable_early_data = true;
    config.max_early_data_size = 0;
    let result = verify_config(&config);
    assert!(result.is_err(), "Early data with zero size should fail");
}

#[test]
fn test_verify_config_early_data_valid_size() {
    let mut config = Tls13Config::default();
    config.enable_early_data = true;
    config.max_early_data_size = 16384;
    let result = verify_config(&config);
    assert!(result.is_ok(), "Early data with valid size should pass");
}

#[test]
fn test_verify_config_all_modes() {
    for mode in [TlsMode::Classic, TlsMode::Hybrid, TlsMode::Pq] {
        let mut config = Tls13Config::default();
        config.mode = mode;
        let result = verify_config(&config);
        assert!(result.is_ok(), "Mode {:?} should be valid", mode);
    }
}

#[test]
fn test_tls13_config_builders() {
    // Test classic() builder
    let config = Tls13Config::classic();
    assert_eq!(config.mode, TlsMode::Classic);

    // Test hybrid() builder
    let config = Tls13Config::hybrid();
    assert_eq!(config.mode, TlsMode::Hybrid);

    // Test pq() builder
    let config = Tls13Config::pq();
    assert_eq!(config.mode, TlsMode::Pq);

    // Test with_early_data builder
    let config = Tls13Config::default().with_early_data(4096);
    assert!(config.enable_early_data);
    assert_eq!(config.max_early_data_size, 4096);
}

#[test]
fn test_get_secure_cipher_suites() {
    let suites = get_secure_cipher_suites();
    assert!(!suites.is_empty());
}
