//! Property-based tests for `CryptoPolicyEngine` (scheme selector).
//!
//! Tests determinism, security monotonicity, and coverage of all
//! (UseCase, SecurityLevel) combinations.

#![allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use arc_types::config::CoreConfig;
use arc_types::selector::CryptoPolicyEngine;
use arc_types::types::{SecurityLevel, UseCase};
use proptest::prelude::*;

/// Generate an arbitrary SecurityLevel.
fn arb_security_level() -> impl Strategy<Value = SecurityLevel> {
    prop_oneof![
        Just(SecurityLevel::Standard),
        Just(SecurityLevel::High),
        Just(SecurityLevel::Maximum),
        Just(SecurityLevel::Quantum),
    ]
}

/// Generate an arbitrary UseCase.
fn arb_use_case() -> impl Strategy<Value = UseCase> {
    prop_oneof![
        Just(UseCase::SecureMessaging),
        Just(UseCase::EmailEncryption),
        Just(UseCase::VpnTunnel),
        Just(UseCase::ApiSecurity),
        Just(UseCase::FileStorage),
        Just(UseCase::DatabaseEncryption),
        Just(UseCase::CloudStorage),
        Just(UseCase::BackupArchive),
        Just(UseCase::ConfigSecrets),
        Just(UseCase::Authentication),
        Just(UseCase::SessionToken),
        Just(UseCase::DigitalCertificate),
        Just(UseCase::KeyExchange),
        Just(UseCase::FinancialTransactions),
        Just(UseCase::LegalDocuments),
        Just(UseCase::BlockchainTransaction),
        Just(UseCase::HealthcareRecords),
        Just(UseCase::GovernmentClassified),
        Just(UseCase::PaymentCard),
        Just(UseCase::IoTDevice),
        Just(UseCase::FirmwareSigning),
        Just(UseCase::SearchableEncryption),
        Just(UseCase::HomomorphicComputation),
        Just(UseCase::AuditLog),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Determinism: same (UseCase, SecurityLevel) always returns the same scheme.
    #[test]
    fn selector_determinism(
        use_case in arb_use_case(),
        security_level in arb_security_level(),
    ) {
        let config = CoreConfig { security_level, ..CoreConfig::default() };

        let scheme1 = CryptoPolicyEngine::recommend_scheme(&use_case, &config).unwrap();
        let scheme2 = CryptoPolicyEngine::recommend_scheme(&use_case, &config).unwrap();

        prop_assert_eq!(&scheme1, &scheme2, "Same inputs must select same scheme");
    }

    /// Every (UseCase, config) pair returns a non-empty scheme string.
    #[test]
    fn selector_all_combinations_valid(
        use_case in arb_use_case(),
        security_level in arb_security_level(),
    ) {
        let config = CoreConfig { security_level, ..CoreConfig::default() };

        let scheme = CryptoPolicyEngine::recommend_scheme(&use_case, &config).unwrap();

        prop_assert!(!scheme.is_empty(), "Scheme must not be empty");
        // All schemes should be either hybrid or PQ
        prop_assert!(
            scheme.contains("hybrid") || scheme.contains("pq-") || scheme.contains("ml-"),
            "Scheme must be hybrid or PQ, got: {}", scheme
        );
    }

    /// Security monotonicity for encryption: higher security level means
    /// key size >= lower level's key size (via scheme name containing higher param set).
    #[test]
    fn selector_encryption_monotonicity(_seed in any::<u64>()) {
        let data = &[0u8; 32];
        let config_std = CoreConfig { security_level: SecurityLevel::Standard, ..CoreConfig::default() };
        let config_high = CoreConfig { security_level: SecurityLevel::High, ..CoreConfig::default() };
        let config_max = CoreConfig { security_level: SecurityLevel::Maximum, ..CoreConfig::default() };

        let scheme_std = CryptoPolicyEngine::select_encryption_scheme(data, &config_std, None).unwrap();
        let scheme_high = CryptoPolicyEngine::select_encryption_scheme(data, &config_high, None).unwrap();
        let scheme_max = CryptoPolicyEngine::select_encryption_scheme(data, &config_max, None).unwrap();

        // Extract ML-KEM parameter set number from scheme name
        let param_std = extract_kem_param(&scheme_std);
        let param_high = extract_kem_param(&scheme_high);
        let param_max = extract_kem_param(&scheme_max);

        prop_assert!(
            param_std <= param_high,
            "Standard ({}) must have param <= High ({})", scheme_std, scheme_high
        );
        prop_assert!(
            param_high <= param_max,
            "High ({}) must have param <= Maximum ({})", scheme_high, scheme_max
        );
    }

    /// PQ encryption scheme selection covers all security levels.
    #[test]
    fn selector_pq_encryption_all_levels(security_level in arb_security_level()) {
        let config = CoreConfig { security_level, ..CoreConfig::default() };
        let scheme = CryptoPolicyEngine::select_pq_encryption_scheme(&config).unwrap();

        prop_assert!(!scheme.is_empty());
        prop_assert!(scheme.contains("ml-kem"), "PQ encryption must use ML-KEM, got: {}", scheme);
    }

    /// PQ signature scheme selection covers all security levels.
    #[test]
    fn selector_pq_signature_all_levels(security_level in arb_security_level()) {
        let config = CoreConfig { security_level, ..CoreConfig::default() };
        let scheme = CryptoPolicyEngine::select_pq_signature_scheme(&config).unwrap();

        prop_assert!(!scheme.is_empty());
        prop_assert!(scheme.contains("ml-dsa"), "PQ signature must use ML-DSA, got: {}", scheme);
    }

    /// Signature monotonicity: higher security level means higher ML-DSA parameter.
    #[test]
    fn selector_signature_monotonicity(_seed in any::<u64>()) {
        let config_std = CoreConfig { security_level: SecurityLevel::Standard, ..CoreConfig::default() };
        let config_high = CoreConfig { security_level: SecurityLevel::High, ..CoreConfig::default() };
        let config_max = CoreConfig { security_level: SecurityLevel::Maximum, ..CoreConfig::default() };

        let scheme_std = CryptoPolicyEngine::select_pq_signature_scheme(&config_std).unwrap();
        let scheme_high = CryptoPolicyEngine::select_pq_signature_scheme(&config_high).unwrap();
        let scheme_max = CryptoPolicyEngine::select_pq_signature_scheme(&config_max).unwrap();

        let param_std = extract_dsa_param(&scheme_std);
        let param_high = extract_dsa_param(&scheme_high);
        let param_max = extract_dsa_param(&scheme_max);

        prop_assert!(
            param_std <= param_high,
            "Standard ({}) must have param <= High ({})", scheme_std, scheme_high
        );
        prop_assert!(
            param_high <= param_max,
            "High ({}) must have param <= Maximum ({})", scheme_high, scheme_max
        );
    }
}

/// Extract ML-KEM parameter set number (512, 768, 1024) from scheme name.
fn extract_kem_param(scheme: &str) -> u32 {
    if scheme.contains("1024") {
        1024
    } else if scheme.contains("768") {
        768
    } else if scheme.contains("512") {
        512
    } else {
        0
    }
}

/// Extract ML-DSA parameter set number (44, 65, 87) from scheme name.
fn extract_dsa_param(scheme: &str) -> u32 {
    if scheme.contains("87") {
        87
    } else if scheme.contains("65") {
        65
    } else if scheme.contains("44") {
        44
    } else {
        0
    }
}
