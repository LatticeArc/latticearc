#![allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic_in_result_fn,
    clippy::unnecessary_wraps,
    clippy::redundant_clone,
    clippy::useless_vec,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::clone_on_copy,
    clippy::len_zero,
    clippy::single_match,
    clippy::unnested_or_patterns,
    clippy::default_constructed_unit_structs,
    clippy::redundant_closure_for_method_calls,
    clippy::semicolon_if_nothing_returned,
    clippy::unnecessary_unwrap,
    clippy::redundant_pattern_matching,
    clippy::missing_const_for_thread_local,
    clippy::get_first,
    clippy::float_cmp,
    clippy::needless_borrows_for_generic_args,
    unused_qualifications
)]

//! Tests for arc-core library initialization and FIPS 140-3 self-tests.

use arc_core::config::CoreConfig;

// ==========================================================================
// VERSION constant
// ==========================================================================

#[test]
fn test_version_is_non_empty() {
    assert!(!arc_core::VERSION.is_empty(), "VERSION should not be empty");
}

#[test]
fn test_version_has_semver_format() {
    let parts: Vec<&str> = arc_core::VERSION.split('.').collect();
    assert!(
        parts.len() >= 2,
        "VERSION should be semver (major.minor[.patch]): {}",
        arc_core::VERSION
    );
    // Major and minor should be numeric
    assert!(parts[0].parse::<u32>().is_ok(), "Major version should be numeric: {}", parts[0]);
    assert!(parts[1].parse::<u32>().is_ok(), "Minor version should be numeric: {}", parts[1]);
}

// ==========================================================================
// init() and init_with_config()
// ==========================================================================

#[test]
fn test_init_succeeds() {
    let result = arc_core::init();
    assert!(result.is_ok(), "init() should succeed: {:?}", result.err());
}

#[test]
fn test_init_with_default_config_succeeds() {
    let config = CoreConfig::default();
    let result = arc_core::init_with_config(&config);
    assert!(result.is_ok(), "init_with_config(default) should succeed: {:?}", result.err());
}

#[test]
fn test_init_sets_self_tests_passed() {
    // After init(), self_tests_passed() should return true
    let _ = arc_core::init();
    assert!(arc_core::self_tests_passed(), "self_tests_passed() should be true after init()");
}

#[test]
fn test_init_idempotent() {
    // Calling init() multiple times should succeed each time
    let result1 = arc_core::init();
    assert!(result1.is_ok());
    let result2 = arc_core::init();
    assert!(result2.is_ok());
    assert!(arc_core::self_tests_passed());
}

#[test]
fn test_init_with_config_idempotent() {
    let config = CoreConfig::default();
    let result1 = arc_core::init_with_config(&config);
    assert!(result1.is_ok());
    let result2 = arc_core::init_with_config(&config);
    assert!(result2.is_ok());
}

// ==========================================================================
// self_tests_passed() behavior
// ==========================================================================

#[test]
fn test_self_tests_passed_returns_bool() {
    // Just ensure it returns without panicking
    let _passed = arc_core::self_tests_passed();
}

// ==========================================================================
// init_with_config with various configs
// ==========================================================================

#[test]
fn test_init_with_high_security_config() {
    let config = CoreConfig::default().with_security_level(arc_core::SecurityLevel::High);
    let result = arc_core::init_with_config(&config);
    assert!(result.is_ok());
}

#[test]
fn test_init_with_maximum_security_config() {
    let config = CoreConfig::default().with_security_level(arc_core::SecurityLevel::Maximum);
    let result = arc_core::init_with_config(&config);
    assert!(result.is_ok());
}

#[test]
fn test_init_with_standard_security_config() {
    let config = CoreConfig::default().with_security_level(arc_core::SecurityLevel::Standard);
    let result = arc_core::init_with_config(&config);
    assert!(result.is_ok());
}

#[test]
fn test_init_with_quantum_security_config() {
    let config = CoreConfig::default().with_security_level(arc_core::SecurityLevel::Quantum);
    let result = arc_core::init_with_config(&config);
    assert!(result.is_ok());
}

// ==========================================================================
// Re-export verification (ensures lib.rs pub use statements are exercised)
// ==========================================================================

#[test]
fn test_crypto_config_reexport() {
    // Verify CryptoConfig is accessible via arc_core
    let config = arc_core::CryptoConfig::new();
    // Just verify it exists and can be created
    let _selection = config.get_selection();
}

#[test]
fn test_security_level_reexport() {
    // Verify SecurityLevel variants are accessible
    let _standard = arc_core::SecurityLevel::Standard;
    let _high = arc_core::SecurityLevel::High;
    let _maximum = arc_core::SecurityLevel::Maximum;
    let _quantum = arc_core::SecurityLevel::Quantum;
}

#[test]
fn test_use_case_reexport() {
    // Verify UseCase variants are accessible
    let _fs = arc_core::UseCase::FileStorage;
    let _msg = arc_core::UseCase::SecureMessaging;
    let _auth = arc_core::UseCase::Authentication;
    let _iot = arc_core::UseCase::IoTDevice;
}

#[test]
fn test_core_error_reexport() {
    // Verify CoreError is accessible
    let err = arc_core::CoreError::InvalidInput("test".to_string());
    let msg = format!("{}", err);
    assert!(msg.contains("test"));
}

#[test]
fn test_key_lifecycle_reexport() {
    // Verify KeyLifecycleState is accessible
    let _active = arc_core::KeyLifecycleState::Active;
    let _rotating = arc_core::KeyLifecycleState::Rotating;
    let _retired = arc_core::KeyLifecycleState::Retired;
    let _destroyed = arc_core::KeyLifecycleState::Destroyed;
}

#[test]
fn test_trust_level_reexport() {
    // Verify TrustLevel is accessible
    let _untrusted = arc_core::TrustLevel::Untrusted;
    let _partial = arc_core::TrustLevel::Partial;
    let _trusted = arc_core::TrustLevel::Trusted;
    let _fully = arc_core::TrustLevel::FullyTrusted;
}

#[test]
fn test_security_mode_unverified() {
    let mode = arc_core::SecurityMode::Unverified;
    assert!(mode.validate().is_ok());
}

// ==========================================================================
// Convenience function re-exports (just verify they're accessible)
// ==========================================================================

#[test]
fn test_generate_keypair_reexport() {
    let result = arc_core::generate_keypair();
    assert!(result.is_ok());
    let (pk, sk) = result.unwrap();
    assert!(!pk.is_empty());
    assert!(!sk.as_ref().is_empty());
}

#[test]
fn test_encrypt_decrypt_reexport() {
    let key = [0x42u8; 32];
    let data = b"test reexport";
    let config = arc_core::CryptoConfig::new();

    let encrypted = arc_core::encrypt(data, &key, config.clone()).unwrap();
    let decrypted = arc_core::decrypt(&encrypted, &key, config).unwrap();
    assert_eq!(decrypted, data);
}

#[test]
fn test_hash_data_reexport() {
    let result = arc_core::hash_data(b"test");
    assert_eq!(result.len(), 32); // SHA3-256 is 32 bytes
}

#[test]
fn test_hmac_reexport() {
    let key = [0x42u8; 32];
    let result = arc_core::hmac(b"test", &key, arc_core::SecurityMode::Unverified);
    assert!(result.is_ok());
}

#[test]
fn test_derive_key_reexport() {
    let ikm = [0x42u8; 32];
    let salt = [0x00u8; 16];
    let result = arc_core::derive_key(&ikm, &salt, 32, arc_core::SecurityMode::Unverified);
    assert!(result.is_ok());
}

// ==========================================================================
// Selector re-exports
// ==========================================================================

#[test]
fn test_crypto_policy_engine_reexport() {
    let config = CoreConfig::default();
    let result =
        arc_core::CryptoPolicyEngine::select_encryption_scheme(b"test data", &config, None);
    assert!(result.is_ok());
}

#[test]
fn test_scheme_constants_reexport() {
    // Verify scheme constants are accessible
    assert!(!arc_core::DEFAULT_ENCRYPTION_SCHEME.is_empty());
    assert!(!arc_core::DEFAULT_SIGNATURE_SCHEME.is_empty());
    assert!(!arc_core::CLASSICAL_AES_GCM.is_empty());
    assert!(!arc_core::CLASSICAL_ED25519.is_empty());
}
