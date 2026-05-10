#![deny(unsafe_code)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::float_cmp)]

//! Coverage tests for `CryptoPolicyEngine` trait implementations and uncovered paths.

use latticearc::types::traits::{PatternType, SchemeSelector};
use latticearc::unified_api::{
    CoreConfig, CryptoContext, CryptoPolicyEngine, PerformancePreference, SecurityLevel, UseCase,
};

// ============================================================================
// SchemeSelector trait impl on CryptoPolicyEngine
// ============================================================================

#[test]
fn test_scheme_selector_select_encryption_scheme_succeeds() {
    // `hardware_acceleration = false` only succeeds at `Standard`;
    // higher levels refuse the symmetric-only fallback.
    let engine = CryptoPolicyEngine::new();
    let ctx = CryptoContext::new(SecurityLevel::Standard, PerformancePreference::Balanced, None)
        .with_hardware_acceleration(false);
    let result = engine.select_encryption_scheme(b"test data", &ctx);
    assert!(result.is_ok());
    let scheme = result.unwrap();
    assert!(!scheme.is_empty());
}

#[test]
fn test_scheme_selector_select_encryption_scheme_with_use_case_succeeds() {
    let engine = CryptoPolicyEngine::new();
    let ctx = CryptoContext::new(
        SecurityLevel::Maximum,
        PerformancePreference::Balanced,
        Some(UseCase::SecureMessaging),
    )
    .with_hardware_acceleration(false);
    let result = engine.select_encryption_scheme(b"important message", &ctx);
    assert!(result.is_ok());
}

#[test]
fn test_scheme_selector_select_encryption_scheme_speed_succeeds() {
    let engine = CryptoPolicyEngine::new();
    let ctx = CryptoContext::new(SecurityLevel::Standard, PerformancePreference::Speed, None);
    let result = engine.select_encryption_scheme(b"fast", &ctx);
    assert!(result.is_ok());
}

#[test]
fn test_scheme_selector_select_signature_scheme_succeeds() {
    let engine = CryptoPolicyEngine::new();
    let ctx = CryptoContext::new(SecurityLevel::High, PerformancePreference::Balanced, None)
        .with_hardware_acceleration(false);
    let result = engine.select_signature_scheme(&ctx);
    assert!(result.is_ok());
    let scheme = result.unwrap();
    assert!(!scheme.is_empty());
}

#[test]
fn test_scheme_selector_select_signature_scheme_maximum_succeeds() {
    let engine = CryptoPolicyEngine::new();
    let ctx = CryptoContext::new(
        SecurityLevel::Maximum,
        PerformancePreference::Balanced,
        Some(UseCase::GovernmentClassified),
    );
    let result = engine.select_signature_scheme(&ctx);
    assert!(result.is_ok());
}

#[test]
fn test_scheme_selector_select_signature_scheme_maximum_no_usecase_memory_succeeds() {
    let engine = CryptoPolicyEngine::new();
    let ctx = CryptoContext::new(SecurityLevel::Maximum, PerformancePreference::Memory, None)
        .with_hardware_acceleration(false);
    let result = engine.select_signature_scheme(&ctx);
    assert!(result.is_ok());
}

#[test]
fn test_scheme_selector_analyze_data_characteristics_random_is_correct() {
    let engine = CryptoPolicyEngine::new();
    // High-entropy random data
    let data: Vec<u8> = (0..256).map(|i| (i % 256) as u8).collect();
    let chars = engine.analyze_data_characteristics(&data);
    assert!(chars.entropy > 0.0);
    assert!(chars.size > 0);
}

#[test]
fn test_scheme_selector_analyze_data_characteristics_text_is_correct() {
    let engine = CryptoPolicyEngine::new();
    let data = b"Hello, this is a text message with enough content to analyze properly.";
    let chars = engine.analyze_data_characteristics(data);
    assert_eq!(chars.pattern_type, PatternType::Text);
    assert_eq!(chars.size, data.len());
}

#[test]
fn test_scheme_selector_analyze_data_characteristics_empty_is_correct() {
    let engine = CryptoPolicyEngine::new();
    let chars = engine.analyze_data_characteristics(b"");
    assert_eq!(chars.size, 0);
    assert_eq!(chars.entropy, 0.0);
}

#[test]
fn test_scheme_selector_analyze_data_characteristics_repetitive_is_correct() {
    let engine = CryptoPolicyEngine::new();
    // Repetitive data: same 8-byte chunk repeated many times
    let chunk = [0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89];
    let mut data = Vec::new();
    for _ in 0..100 {
        data.extend_from_slice(&chunk);
    }
    let chars = engine.analyze_data_characteristics(&data);
    assert_eq!(chars.pattern_type, PatternType::Repetitive);
}

// ============================================================================
// CryptoPolicyEngine static methods with various configs
// ============================================================================

#[test]
fn test_select_encryption_scheme_speed_preference_small_data_succeeds() {
    let config = CoreConfig {
        security_level: SecurityLevel::Standard,
        performance_preference: PerformancePreference::Speed,
        hardware_acceleration: false,
        fallback_enabled: true,
        strict_validation: false,
    };
    let result = CryptoPolicyEngine::select_encryption_scheme(b"tiny", &config, None);
    assert!(result.is_ok());
}

#[test]
fn test_select_encryption_scheme_with_financial_use_case_succeeds() {
    let config = CoreConfig::default();
    let result = CryptoPolicyEngine::select_encryption_scheme(
        b"financial data",
        &config,
        Some(&UseCase::FinancialTransactions),
    );
    assert!(result.is_ok());
}

#[test]
fn test_select_encryption_scheme_with_iot_use_case_succeeds() {
    let config = CoreConfig::default();
    let result = CryptoPolicyEngine::select_encryption_scheme(
        b"sensor data",
        &config,
        Some(&UseCase::IoTDevice),
    );
    assert!(result.is_ok());
}

#[test]
fn test_select_encryption_scheme_with_healthcare_use_case_succeeds() {
    let config = CoreConfig::default();
    let result = CryptoPolicyEngine::select_encryption_scheme(
        b"patient data",
        &config,
        Some(&UseCase::HealthcareRecords),
    );
    assert!(result.is_ok());
}

#[test]
fn test_select_signature_scheme_various_levels_succeeds() {
    let levels = [SecurityLevel::Standard, SecurityLevel::High, SecurityLevel::Maximum];
    for level in &levels {
        let config = CoreConfig {
            security_level: *level,
            performance_preference: PerformancePreference::Balanced,
            hardware_acceleration: false,
            fallback_enabled: true,
            strict_validation: false,
        };
        let result = CryptoPolicyEngine::select_signature_scheme(&config);
        assert!(result.is_ok(), "Failed for level {:?}", level);
    }
}

// ============================================================================
// CryptoPolicyEngine::default_scheme and Default
// ============================================================================

#[test]
fn test_default_scheme_is_correct() {
    let scheme = CryptoPolicyEngine::default_scheme();
    assert!(!scheme.is_empty());
    assert!(scheme.contains("hybrid"));
}

#[test]
fn test_crypto_policy_engine_default_succeeds() {
    let _engine: CryptoPolicyEngine = Default::default();
}
