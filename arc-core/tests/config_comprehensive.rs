//! Comprehensive tests for Config and Policy modules
//!
//! This test suite validates all configuration types, builder patterns, validation rules,
//! and algorithm selection logic in arc-core.
//!
//! # Test Coverage (Tasks 1.9.1-1.9.10)
//!
//! 1.9.1 - All UseCase variants
//! 1.9.2 - All SecurityLevel variants
//! 1.9.3 - CoreConfig::default()
//! 1.9.4 - Builder pattern
//! 1.9.5 - Config validation success/failure
//! 1.9.6 - Algorithm selector for each use case
//! 1.9.7 - Security level constraints
//! 1.9.8 - Custom preferences

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

use arc_core::{
    config::{
        CoreConfig, EncryptionConfig, HardwareConfig, ProofComplexity, SignatureConfig,
        UseCaseConfig, ZeroTrustConfig,
    },
    error::CoreError,
    traits::HardwareType,
    types::{
        AlgorithmSelection, CryptoConfig, CryptoContext, CryptoScheme, PerformancePreference,
        SecurityLevel, UseCase,
    },
};

// ============================================================================
// Test 1.9.1: All UseCase Variants
// ============================================================================

#[test]
fn test_use_case_secure_messaging() {
    let config = UseCaseConfig::new(UseCase::SecureMessaging);
    assert_eq!(config.use_case, UseCase::SecureMessaging);
    assert_eq!(config.encryption.base.performance_preference, PerformancePreference::Speed);
}

#[test]
fn test_use_case_email_encryption() {
    let config = UseCaseConfig::new(UseCase::EmailEncryption);
    assert_eq!(config.use_case, UseCase::EmailEncryption);
    assert_eq!(config.encryption.base.security_level, SecurityLevel::High);
}

#[test]
fn test_use_case_vpn_tunnel() {
    let config = UseCaseConfig::new(UseCase::VpnTunnel);
    assert_eq!(config.use_case, UseCase::VpnTunnel);
    assert_eq!(config.encryption.base.performance_preference, PerformancePreference::Speed);
    assert!(config.encryption.base.hardware_acceleration);
}

#[test]
fn test_use_case_api_security() {
    let config = UseCaseConfig::new(UseCase::ApiSecurity);
    assert_eq!(config.use_case, UseCase::ApiSecurity);
    assert_eq!(config.encryption.base.performance_preference, PerformancePreference::Speed);
}

#[test]
fn test_use_case_file_storage() {
    let config = UseCaseConfig::new(UseCase::FileStorage);
    assert_eq!(config.use_case, UseCase::FileStorage);
    assert_eq!(config.encryption.base.security_level, SecurityLevel::Maximum);
}

#[test]
fn test_use_case_database_encryption() {
    let config = UseCaseConfig::new(UseCase::DatabaseEncryption);
    assert_eq!(config.use_case, UseCase::DatabaseEncryption);
    assert_eq!(config.encryption.base.performance_preference, PerformancePreference::Memory);
}

#[test]
fn test_use_case_cloud_storage() {
    let config = UseCaseConfig::new(UseCase::CloudStorage);
    assert_eq!(config.use_case, UseCase::CloudStorage);
    assert_eq!(config.encryption.base.security_level, SecurityLevel::Maximum);
}

#[test]
fn test_use_case_backup_archive() {
    let config = UseCaseConfig::new(UseCase::BackupArchive);
    assert_eq!(config.use_case, UseCase::BackupArchive);
    assert_eq!(config.encryption.base.security_level, SecurityLevel::Maximum);
}

#[test]
fn test_use_case_config_secrets() {
    let config = UseCaseConfig::new(UseCase::ConfigSecrets);
    assert_eq!(config.use_case, UseCase::ConfigSecrets);
    assert_eq!(config.encryption.base.performance_preference, PerformancePreference::Memory);
}

#[test]
fn test_use_case_authentication() {
    let config = UseCaseConfig::new(UseCase::Authentication);
    assert_eq!(config.use_case, UseCase::Authentication);
    assert_eq!(config.encryption.base.security_level, SecurityLevel::Maximum);
}

#[test]
fn test_use_case_session_token() {
    let config = UseCaseConfig::new(UseCase::SessionToken);
    assert_eq!(config.use_case, UseCase::SessionToken);
    assert_eq!(config.encryption.base.performance_preference, PerformancePreference::Speed);
}

#[test]
fn test_use_case_digital_certificate() {
    let config = UseCaseConfig::new(UseCase::DigitalCertificate);
    assert_eq!(config.use_case, UseCase::DigitalCertificate);
    assert_eq!(config.encryption.base.security_level, SecurityLevel::Maximum);
}

#[test]
fn test_use_case_key_exchange() {
    let config = UseCaseConfig::new(UseCase::KeyExchange);
    assert_eq!(config.use_case, UseCase::KeyExchange);
    assert_eq!(config.encryption.base.security_level, SecurityLevel::Maximum);
}

#[test]
fn test_use_case_financial_transactions() {
    let config = UseCaseConfig::new(UseCase::FinancialTransactions);
    assert_eq!(config.use_case, UseCase::FinancialTransactions);
    assert_eq!(config.encryption.base.security_level, SecurityLevel::Maximum);
}

#[test]
fn test_use_case_legal_documents() {
    let config = UseCaseConfig::new(UseCase::LegalDocuments);
    assert_eq!(config.use_case, UseCase::LegalDocuments);
    assert_eq!(config.encryption.base.security_level, SecurityLevel::Maximum);
}

#[test]
fn test_use_case_blockchain_transaction() {
    let config = UseCaseConfig::new(UseCase::BlockchainTransaction);
    assert_eq!(config.use_case, UseCase::BlockchainTransaction);
    assert_eq!(config.encryption.base.performance_preference, PerformancePreference::Balanced);
}

#[test]
fn test_use_case_healthcare_records() {
    let config = UseCaseConfig::new(UseCase::HealthcareRecords);
    assert_eq!(config.use_case, UseCase::HealthcareRecords);
    assert_eq!(config.encryption.base.security_level, SecurityLevel::Maximum);
}

#[test]
fn test_use_case_government_classified() {
    let config = UseCaseConfig::new(UseCase::GovernmentClassified);
    assert_eq!(config.use_case, UseCase::GovernmentClassified);
    assert_eq!(config.encryption.base.security_level, SecurityLevel::Maximum);
}

#[test]
fn test_use_case_payment_card() {
    let config = UseCaseConfig::new(UseCase::PaymentCard);
    assert_eq!(config.use_case, UseCase::PaymentCard);
    assert_eq!(config.encryption.base.security_level, SecurityLevel::Maximum);
}

#[test]
fn test_use_case_iot_device() {
    let config = UseCaseConfig::new(UseCase::IoTDevice);
    assert_eq!(config.use_case, UseCase::IoTDevice);
    assert_eq!(config.encryption.base.security_level, SecurityLevel::Standard);
    assert_eq!(config.encryption.base.performance_preference, PerformancePreference::Memory);
}

#[test]
fn test_use_case_firmware_signing() {
    let config = UseCaseConfig::new(UseCase::FirmwareSigning);
    assert_eq!(config.use_case, UseCase::FirmwareSigning);
    assert_eq!(config.encryption.base.security_level, SecurityLevel::High);
}

#[test]
fn test_use_case_searchable_encryption() {
    let config = UseCaseConfig::new(UseCase::SearchableEncryption);
    assert_eq!(config.use_case, UseCase::SearchableEncryption);
    // Uses default config
    assert_eq!(config.encryption.base.security_level, SecurityLevel::High);
}

#[test]
fn test_use_case_homomorphic_computation() {
    let config = UseCaseConfig::new(UseCase::HomomorphicComputation);
    assert_eq!(config.use_case, UseCase::HomomorphicComputation);
    assert_eq!(config.encryption.base.security_level, SecurityLevel::Maximum);
    assert!(config.encryption.base.hardware_acceleration);
}

#[test]
fn test_use_case_audit_log() {
    let config = UseCaseConfig::new(UseCase::AuditLog);
    assert_eq!(config.use_case, UseCase::AuditLog);
    assert_eq!(config.encryption.base.security_level, SecurityLevel::High);
}

// ============================================================================
// Test 1.9.2: All SecurityLevel Variants
// ============================================================================

#[test]
fn test_security_level_standard() {
    let level = SecurityLevel::Standard;
    assert_ne!(level, SecurityLevel::High);
    assert_ne!(level, SecurityLevel::Maximum);
    assert_ne!(level, SecurityLevel::Quantum);
}

#[test]
fn test_security_level_high() {
    let level = SecurityLevel::High;
    assert_ne!(level, SecurityLevel::Standard);
    assert_ne!(level, SecurityLevel::Maximum);
    assert_ne!(level, SecurityLevel::Quantum);
}

#[test]
fn test_security_level_maximum() {
    let level = SecurityLevel::Maximum;
    assert_ne!(level, SecurityLevel::Standard);
    assert_ne!(level, SecurityLevel::High);
    assert_ne!(level, SecurityLevel::Quantum);
}

#[test]
fn test_security_level_quantum() {
    let level = SecurityLevel::Quantum;
    assert_ne!(level, SecurityLevel::Standard);
    assert_ne!(level, SecurityLevel::High);
    assert_ne!(level, SecurityLevel::Maximum);
}

#[test]
fn test_security_level_default_is_high() {
    let level = SecurityLevel::default();
    assert_eq!(level, SecurityLevel::High);
}

#[test]
fn test_security_level_clone_and_eq() {
    let level1 = SecurityLevel::Maximum;
    let level2 = level1.clone();
    assert_eq!(level1, level2);
}

#[test]
fn test_security_level_debug_format() {
    let level = SecurityLevel::High;
    let debug_str = format!("{:?}", level);
    assert!(debug_str.contains("High"));
}

// ============================================================================
// Test 1.9.3: CoreConfig::default()
// ============================================================================

#[test]
fn test_core_config_default_values() {
    let config = CoreConfig::default();

    assert_eq!(config.security_level, SecurityLevel::High);
    assert_eq!(config.performance_preference, PerformancePreference::Balanced);
    assert!(config.hardware_acceleration);
    assert!(config.fallback_enabled);
    assert!(config.strict_validation);
}

#[test]
fn test_core_config_new_equals_default() {
    let new_config = CoreConfig::new();
    let default_config = CoreConfig::default();

    assert_eq!(new_config, default_config);
}

#[test]
fn test_core_config_for_development() {
    let config = CoreConfig::for_development();

    assert_eq!(config.security_level, SecurityLevel::Standard);
    assert!(!config.strict_validation);
    // Other fields retain defaults
    assert_eq!(config.performance_preference, PerformancePreference::Balanced);
}

#[test]
fn test_core_config_for_production() {
    let config = CoreConfig::for_production();

    assert_eq!(config.security_level, SecurityLevel::Maximum);
    assert!(config.strict_validation);
    assert!(config.hardware_acceleration);
}

// ============================================================================
// Test 1.9.4: Builder Pattern
// ============================================================================

#[test]
fn test_core_config_builder_security_level() {
    let config = CoreConfig::new().with_security_level(SecurityLevel::Maximum);
    assert_eq!(config.security_level, SecurityLevel::Maximum);
}

#[test]
fn test_core_config_builder_performance_preference() {
    let config = CoreConfig::new().with_performance_preference(PerformancePreference::Speed);
    assert_eq!(config.performance_preference, PerformancePreference::Speed);
}

#[test]
fn test_core_config_builder_hardware_acceleration() {
    let config = CoreConfig::new().with_hardware_acceleration(false);
    assert!(!config.hardware_acceleration);
}

#[test]
fn test_core_config_builder_fallback() {
    let config = CoreConfig::new().with_fallback(false);
    assert!(!config.fallback_enabled);
}

#[test]
fn test_core_config_builder_strict_validation() {
    let config = CoreConfig::new().with_strict_validation(false);
    assert!(!config.strict_validation);
}

#[test]
fn test_core_config_builder_chaining() {
    let config = CoreConfig::new()
        .with_security_level(SecurityLevel::Maximum)
        .with_performance_preference(PerformancePreference::Speed)
        .with_hardware_acceleration(true)
        .with_fallback(true)
        .with_strict_validation(true);

    assert_eq!(config.security_level, SecurityLevel::Maximum);
    assert_eq!(config.performance_preference, PerformancePreference::Speed);
    assert!(config.hardware_acceleration);
    assert!(config.fallback_enabled);
    assert!(config.strict_validation);
}

#[test]
fn test_core_config_builder_overwrite() {
    let config = CoreConfig::new()
        .with_security_level(SecurityLevel::Standard)
        .with_security_level(SecurityLevel::Maximum);

    assert_eq!(
        config.security_level,
        SecurityLevel::Maximum,
        "Later call should overwrite earlier"
    );
}

// ============================================================================
// Test 1.9.5: Config Validation Success/Failure
// ============================================================================

#[test]
fn test_core_config_validation_success() {
    let config = CoreConfig::new()
        .with_security_level(SecurityLevel::Maximum)
        .with_hardware_acceleration(true);

    assert!(
        config.validate().is_ok(),
        "Maximum security with hardware acceleration should validate"
    );
}

#[test]
fn test_core_config_validation_success_high_security() {
    let config = CoreConfig::new()
        .with_security_level(SecurityLevel::High)
        .with_hardware_acceleration(false);

    assert!(
        config.validate().is_ok(),
        "High security without hardware acceleration should validate"
    );
}

#[test]
fn test_core_config_validation_failure_max_security_no_hw() {
    let config = CoreConfig::new()
        .with_security_level(SecurityLevel::Maximum)
        .with_hardware_acceleration(false);

    let result = config.validate();
    assert!(result.is_err());

    match result {
        Err(CoreError::ConfigurationError(msg)) => {
            assert!(msg.contains("hardware acceleration"));
        }
        _ => panic!("Expected ConfigurationError"),
    }
}

#[test]
fn test_core_config_validation_failure_speed_no_fallback() {
    let config = CoreConfig::new()
        .with_performance_preference(PerformancePreference::Speed)
        .with_fallback(false);

    let result = config.validate();
    assert!(result.is_err());

    match result {
        Err(CoreError::ConfigurationError(msg)) => {
            assert!(msg.contains("fallback"));
        }
        _ => panic!("Expected ConfigurationError"),
    }
}

#[test]
fn test_core_config_build_success() {
    let result = CoreConfig::new()
        .with_security_level(SecurityLevel::High)
        .with_hardware_acceleration(true)
        .build();

    assert!(result.is_ok());
    let config = result.expect("build should succeed");
    assert_eq!(config.security_level, SecurityLevel::High);
}

#[test]
fn test_core_config_build_failure() {
    let result = CoreConfig::new()
        .with_security_level(SecurityLevel::Maximum)
        .with_hardware_acceleration(false)
        .build();

    assert!(result.is_err());
}

#[test]
fn test_encryption_config_validation_success() {
    let config = EncryptionConfig::new().with_compression(true).with_integrity_check(true);

    assert!(config.validate().is_ok());
}

#[test]
fn test_encryption_config_validation_failure_compression_without_integrity() {
    let config = EncryptionConfig::new().with_compression(true).with_integrity_check(false);

    let result = config.validate();
    assert!(result.is_err());

    match result {
        Err(CoreError::ConfigurationError(msg)) => {
            assert!(msg.contains("Compression") || msg.contains("integrity"));
        }
        _ => panic!("Expected ConfigurationError"),
    }
}

#[test]
fn test_signature_config_validation_success() {
    let config = SignatureConfig::new().with_timestamp(true).with_certificate_chain(true);

    assert!(config.validate().is_ok());
}

#[test]
fn test_signature_config_validation_failure_cert_chain_without_timestamp() {
    let config = SignatureConfig::new().with_timestamp(false).with_certificate_chain(true);

    let result = config.validate();
    assert!(result.is_err());

    match result {
        Err(CoreError::ConfigurationError(msg)) => {
            assert!(msg.contains("timestamp") || msg.contains("Certificate"));
        }
        _ => panic!("Expected ConfigurationError"),
    }
}

#[test]
fn test_zero_trust_config_validation_success() {
    let config = ZeroTrustConfig::new()
        .with_timeout(5000)
        .with_continuous_verification(true)
        .with_verification_interval(1000);

    assert!(config.validate().is_ok());
}

#[test]
fn test_zero_trust_config_validation_failure_zero_timeout() {
    let config = ZeroTrustConfig::new().with_timeout(0);

    let result = config.validate();
    assert!(result.is_err());

    match result {
        Err(CoreError::ConfigurationError(msg)) => {
            assert!(msg.contains("timeout") || msg.contains("zero"));
        }
        _ => panic!("Expected ConfigurationError"),
    }
}

#[test]
fn test_zero_trust_config_validation_failure_continuous_zero_interval() {
    let config =
        ZeroTrustConfig::new().with_continuous_verification(true).with_verification_interval(0);

    let result = config.validate();
    assert!(result.is_err());

    match result {
        Err(CoreError::ConfigurationError(msg)) => {
            assert!(msg.contains("interval") || msg.contains("Continuous"), "Got: {}", msg);
        }
        _ => panic!("Expected ConfigurationError"),
    }
}

#[test]
fn test_hardware_config_validation_success() {
    let config =
        HardwareConfig::new().with_acceleration(true).with_fallback(true).with_threshold(4096);

    assert!(config.validate().is_ok());
}

#[test]
fn test_hardware_config_validation_failure_zero_threshold() {
    let config = HardwareConfig::new().with_threshold(0);

    let result = config.validate();
    assert!(result.is_err());
}

#[test]
fn test_hardware_config_validation_failure_force_cpu_with_acceleration() {
    let config = HardwareConfig::new().with_acceleration(true).with_force_cpu(true);

    let result = config.validate();
    assert!(result.is_err());

    match result {
        Err(CoreError::ConfigurationError(msg)) => {
            assert!(msg.contains("CPU") || msg.contains("acceleration"));
        }
        _ => panic!("Expected ConfigurationError"),
    }
}

// ============================================================================
// Test 1.9.6: Algorithm Selector for Each Use Case
// ============================================================================

#[test]
fn test_algorithm_selection_by_use_case() {
    let selection = AlgorithmSelection::UseCase(UseCase::FinancialTransactions);
    match selection {
        AlgorithmSelection::UseCase(uc) => assert_eq!(uc, UseCase::FinancialTransactions),
        _ => panic!("Expected UseCase variant"),
    }
}

#[test]
fn test_algorithm_selection_by_security_level() {
    let selection = AlgorithmSelection::SecurityLevel(SecurityLevel::Maximum);
    match selection {
        AlgorithmSelection::SecurityLevel(sl) => assert_eq!(sl, SecurityLevel::Maximum),
        _ => panic!("Expected SecurityLevel variant"),
    }
}

#[test]
fn test_algorithm_selection_default() {
    let selection = AlgorithmSelection::default();
    match selection {
        AlgorithmSelection::SecurityLevel(sl) => assert_eq!(sl, SecurityLevel::High),
        _ => panic!("Expected default to be SecurityLevel::High"),
    }
}

#[test]
fn test_crypto_config_new() {
    let config = CryptoConfig::new();
    assert!(!config.is_verified());
    match config.get_selection() {
        AlgorithmSelection::SecurityLevel(sl) => assert_eq!(*sl, SecurityLevel::High),
        _ => panic!("Expected default SecurityLevel"),
    }
}

#[test]
fn test_crypto_config_use_case_setter() {
    let config = CryptoConfig::new().use_case(UseCase::HealthcareRecords);
    match config.get_selection() {
        AlgorithmSelection::UseCase(uc) => assert_eq!(*uc, UseCase::HealthcareRecords),
        _ => panic!("Expected UseCase variant"),
    }
}

#[test]
fn test_crypto_config_security_level_setter() {
    let config = CryptoConfig::new().security_level(SecurityLevel::Quantum);
    match config.get_selection() {
        AlgorithmSelection::SecurityLevel(sl) => assert_eq!(*sl, SecurityLevel::Quantum),
        _ => panic!("Expected SecurityLevel variant"),
    }
}

#[test]
fn test_crypto_config_use_case_overrides_security_level() {
    let config = CryptoConfig::new()
        .security_level(SecurityLevel::Standard)
        .use_case(UseCase::GovernmentClassified);

    match config.get_selection() {
        AlgorithmSelection::UseCase(uc) => assert_eq!(*uc, UseCase::GovernmentClassified),
        _ => panic!("UseCase should override SecurityLevel"),
    }
}

#[test]
fn test_crypto_config_security_level_overrides_use_case() {
    let config =
        CryptoConfig::new().use_case(UseCase::IoTDevice).security_level(SecurityLevel::Maximum);

    match config.get_selection() {
        AlgorithmSelection::SecurityLevel(sl) => assert_eq!(*sl, SecurityLevel::Maximum),
        _ => panic!("SecurityLevel should override UseCase"),
    }
}

// ============================================================================
// Test 1.9.7: Security Level Constraints
// ============================================================================

#[test]
fn test_use_case_config_respects_security_constraints() {
    // High-security use cases should have Maximum security level
    let financial = UseCaseConfig::new(UseCase::FinancialTransactions);
    assert_eq!(financial.encryption.base.security_level, SecurityLevel::Maximum);

    let healthcare = UseCaseConfig::new(UseCase::HealthcareRecords);
    assert_eq!(healthcare.encryption.base.security_level, SecurityLevel::Maximum);

    let government = UseCaseConfig::new(UseCase::GovernmentClassified);
    assert_eq!(government.encryption.base.security_level, SecurityLevel::Maximum);

    // IoT should have Standard level for resource constraints
    let iot = UseCaseConfig::new(UseCase::IoTDevice);
    assert_eq!(iot.encryption.base.security_level, SecurityLevel::Standard);
}

#[test]
fn test_use_case_config_validates_all_nested() {
    // All use case configs should pass validation by default
    let use_cases = vec![
        UseCase::SecureMessaging,
        UseCase::EmailEncryption,
        UseCase::VpnTunnel,
        UseCase::FileStorage,
        UseCase::Authentication,
        UseCase::FinancialTransactions,
        UseCase::IoTDevice,
    ];

    for use_case in use_cases {
        let config = UseCaseConfig::new(use_case.clone());
        assert!(config.validate().is_ok(), "UseCaseConfig for {:?} should validate", use_case);
    }
}

#[test]
fn test_crypto_context_default() {
    let ctx = CryptoContext::default();

    assert_eq!(ctx.security_level, SecurityLevel::High);
    assert_eq!(ctx.performance_preference, PerformancePreference::Balanced);
    assert!(ctx.use_case.is_none());
    assert!(ctx.hardware_acceleration);
}

#[test]
fn test_crypto_context_with_use_case() {
    let ctx = CryptoContext {
        security_level: SecurityLevel::Maximum,
        performance_preference: PerformancePreference::Speed,
        use_case: Some(UseCase::VpnTunnel),
        hardware_acceleration: true,
        timestamp: chrono::Utc::now(),
    };

    assert_eq!(ctx.security_level, SecurityLevel::Maximum);
    assert_eq!(ctx.use_case, Some(UseCase::VpnTunnel));
}

// ============================================================================
// Test 1.9.8: Custom Preferences
// ============================================================================

#[test]
fn test_performance_preference_speed() {
    let pref = PerformancePreference::Speed;
    assert_ne!(pref, PerformancePreference::Balanced);
    assert_ne!(pref, PerformancePreference::Memory);
}

#[test]
fn test_performance_preference_memory() {
    let pref = PerformancePreference::Memory;
    assert_ne!(pref, PerformancePreference::Balanced);
    assert_ne!(pref, PerformancePreference::Speed);
}

#[test]
fn test_performance_preference_balanced() {
    let pref = PerformancePreference::Balanced;
    assert_ne!(pref, PerformancePreference::Speed);
    assert_ne!(pref, PerformancePreference::Memory);
}

#[test]
fn test_performance_preference_default() {
    let pref = PerformancePreference::default();
    assert_eq!(pref, PerformancePreference::Balanced);
}

#[test]
fn test_performance_preference_clone() {
    let pref1 = PerformancePreference::Speed;
    let pref2 = pref1.clone();
    assert_eq!(pref1, pref2);
}

// ============================================================================
// Additional Config Type Tests
// ============================================================================

#[test]
fn test_encryption_config_default() {
    let config = EncryptionConfig::default();

    assert!(config.preferred_scheme.is_none());
    assert!(config.compression_enabled);
    assert!(config.integrity_check);
}

#[test]
fn test_encryption_config_with_scheme() {
    let config = EncryptionConfig::new().with_scheme(CryptoScheme::Hybrid);
    assert_eq!(config.preferred_scheme, Some(CryptoScheme::Hybrid));
}

#[test]
fn test_encryption_config_all_schemes() {
    let schemes = vec![
        CryptoScheme::Hybrid,
        CryptoScheme::Symmetric,
        CryptoScheme::Asymmetric,
        CryptoScheme::Homomorphic,
        CryptoScheme::PostQuantum,
    ];

    for scheme in schemes {
        let config = EncryptionConfig::new().with_scheme(scheme.clone());
        assert_eq!(config.preferred_scheme, Some(scheme));
    }
}

#[test]
fn test_signature_config_default() {
    let config = SignatureConfig::default();

    assert!(config.preferred_scheme.is_none());
    assert!(config.timestamp_enabled);
    assert!(!config.certificate_chain);
}

#[test]
fn test_signature_config_builder() {
    let config = SignatureConfig::new()
        .with_scheme(CryptoScheme::PostQuantum)
        .with_timestamp(true)
        .with_certificate_chain(true);

    assert_eq!(config.preferred_scheme, Some(CryptoScheme::PostQuantum));
    assert!(config.timestamp_enabled);
    assert!(config.certificate_chain);
}

#[test]
fn test_zero_trust_config_default() {
    let config = ZeroTrustConfig::default();

    assert_eq!(config.challenge_timeout_ms, 5000);
    assert_eq!(config.proof_complexity, ProofComplexity::Medium);
    assert!(config.continuous_verification);
    assert_eq!(config.verification_interval_ms, 30000);
}

#[test]
fn test_zero_trust_config_builder() {
    let config = ZeroTrustConfig::new()
        .with_timeout(10000)
        .with_complexity(ProofComplexity::High)
        .with_continuous_verification(false)
        .with_verification_interval(60000);

    assert_eq!(config.challenge_timeout_ms, 10000);
    assert_eq!(config.proof_complexity, ProofComplexity::High);
    assert!(!config.continuous_verification);
    assert_eq!(config.verification_interval_ms, 60000);
}

#[test]
fn test_proof_complexity_variants() {
    assert_ne!(ProofComplexity::Low, ProofComplexity::Medium);
    assert_ne!(ProofComplexity::Medium, ProofComplexity::High);
    assert_ne!(ProofComplexity::Low, ProofComplexity::High);
}

#[test]
fn test_hardware_config_default() {
    let config = HardwareConfig::default();

    assert!(config.acceleration_enabled);
    assert!(config.fallback_enabled);
    assert_eq!(config.threshold_bytes, 4096);
    assert!(config.preferred_accelerators.is_empty());
    assert!(!config.force_cpu);
}

#[test]
fn test_hardware_config_builder_with_accelerator() {
    let config = HardwareConfig::new()
        .with_preferred_accelerator(HardwareType::Gpu)
        .with_preferred_accelerator(HardwareType::Fpga);

    assert_eq!(config.preferred_accelerators.len(), 2);
    assert!(config.preferred_accelerators.contains(&HardwareType::Gpu));
    assert!(config.preferred_accelerators.contains(&HardwareType::Fpga));
}

#[test]
fn test_hardware_config_force_cpu_mode() {
    let config = HardwareConfig::new().with_acceleration(false).with_force_cpu(true);

    assert!(!config.acceleration_enabled);
    assert!(config.force_cpu);
    // Should validate when acceleration is disabled
    assert!(config.validate().is_ok());
}

// ============================================================================
// Edge Cases and Boundary Tests
// ============================================================================

#[test]
fn test_config_with_minimum_values() {
    let config = ZeroTrustConfig::new().with_timeout(1).with_verification_interval(1);

    assert!(config.validate().is_ok());
}

#[test]
fn test_config_with_maximum_values() {
    let config = ZeroTrustConfig::new().with_timeout(u64::MAX).with_verification_interval(u64::MAX);

    assert!(config.validate().is_ok());
}

#[test]
fn test_hardware_config_minimum_threshold() {
    let config = HardwareConfig::new().with_threshold(1);
    assert!(config.validate().is_ok());
}

#[test]
fn test_use_case_config_all_nested_configs_consistent() {
    let config = UseCaseConfig::new(UseCase::GovernmentClassified);

    // All nested configs should have the same base security level
    assert_eq!(config.encryption.base.security_level, SecurityLevel::Maximum);
    assert_eq!(config.signature.base.security_level, SecurityLevel::Maximum);
    assert_eq!(config.zero_trust.base.security_level, SecurityLevel::Maximum);
}

// ============================================================================
// Clone and Equality Tests
// ============================================================================

#[test]
fn test_core_config_clone() {
    let config1 = CoreConfig::new()
        .with_security_level(SecurityLevel::Maximum)
        .with_performance_preference(PerformancePreference::Speed);

    let config2 = config1.clone();

    assert_eq!(config1, config2);
}

#[test]
fn test_core_config_equality() {
    let config1 = CoreConfig::new().with_security_level(SecurityLevel::High);
    let config2 = CoreConfig::new().with_security_level(SecurityLevel::High);
    let config3 = CoreConfig::new().with_security_level(SecurityLevel::Maximum);

    assert_eq!(config1, config2);
    assert_ne!(config1, config3);
}

#[test]
fn test_use_case_equality() {
    assert_eq!(UseCase::SecureMessaging, UseCase::SecureMessaging);
    assert_ne!(UseCase::SecureMessaging, UseCase::EmailEncryption);
}

#[test]
fn test_crypto_scheme_equality() {
    assert_eq!(CryptoScheme::Hybrid, CryptoScheme::Hybrid);
    assert_ne!(CryptoScheme::Hybrid, CryptoScheme::Symmetric);
}

// ============================================================================
// Stress Tests
// ============================================================================

#[test]
fn test_create_many_configs() {
    for i in 0..100 {
        let config = CoreConfig::new()
            .with_security_level(if i % 3 == 0 {
                SecurityLevel::Standard
            } else if i % 3 == 1 {
                SecurityLevel::High
            } else {
                SecurityLevel::Maximum
            })
            .with_hardware_acceleration(true);

        assert!(config.validate().is_ok(), "Config {} should validate", i);
    }
}

#[test]
fn test_create_all_use_case_configs() {
    let use_cases = vec![
        UseCase::SecureMessaging,
        UseCase::EmailEncryption,
        UseCase::VpnTunnel,
        UseCase::ApiSecurity,
        UseCase::FileStorage,
        UseCase::DatabaseEncryption,
        UseCase::CloudStorage,
        UseCase::BackupArchive,
        UseCase::ConfigSecrets,
        UseCase::Authentication,
        UseCase::SessionToken,
        UseCase::DigitalCertificate,
        UseCase::KeyExchange,
        UseCase::FinancialTransactions,
        UseCase::LegalDocuments,
        UseCase::BlockchainTransaction,
        UseCase::HealthcareRecords,
        UseCase::GovernmentClassified,
        UseCase::PaymentCard,
        UseCase::IoTDevice,
        UseCase::FirmwareSigning,
        UseCase::SearchableEncryption,
        UseCase::HomomorphicComputation,
        UseCase::AuditLog,
    ];

    for use_case in use_cases {
        let config = UseCaseConfig::new(use_case.clone());
        assert!(config.validate().is_ok(), "UseCaseConfig for {:?} should validate", use_case);
    }
}
