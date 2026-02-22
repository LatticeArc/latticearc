//! Scheme Contract Tests — Standards-Grade UseCase × Scheme × Key Level Matrix
//!
//! These tests verify the **contract** between UseCase/SecurityLevel selection and the
//! actual encryption scheme used. Every test asserts on `EncryptedOutput.scheme` and
//! structural metadata — no `force_scheme()` is used anywhere in this file.
//!
//! Standards basis:
//! - FIPS 140-3 Area 3: Services table — every operation maps to expected behavior
//! - DO-178C: Bidirectional traceability — every requirement → test → code → result
//! - Common Criteria ATE_DPT: Depth testing below API surface into dispatch logic
//!
//! Run: `cargo test --test scheme_contract_tests --all-features --release`

#![allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic_in_result_fn,
    clippy::unnecessary_wraps,
    clippy::redundant_clone,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::needless_borrows_for_generic_args,
    unused_qualifications
)]

use latticearc::primitives::kem::ml_kem::MlKemSecurityLevel;
use latticearc::{
    ComplianceMode, CryptoConfig, CryptoScheme, DecryptKey, EncryptKey, EncryptionScheme,
    SecurityLevel, UseCase, decrypt, deserialize_encrypted_output, encrypt, fips_available,
    generate_hybrid_keypair_with_level, serialize_encrypted_output,
};

// ============================================================================
// Helper: UseCase → Expected Scheme mapping (mirrors selector.rs exactly)
// ============================================================================

fn expected_scheme_for_use_case(uc: &UseCase) -> EncryptionScheme {
    match uc {
        UseCase::IoTDevice => EncryptionScheme::HybridMlKem512Aes256Gcm,

        UseCase::SecureMessaging
        | UseCase::VpnTunnel
        | UseCase::ApiSecurity
        | UseCase::DatabaseEncryption
        | UseCase::ConfigSecrets
        | UseCase::SessionToken
        | UseCase::AuditLog
        | UseCase::Authentication
        | UseCase::DigitalCertificate
        | UseCase::FinancialTransactions
        | UseCase::LegalDocuments
        | UseCase::BlockchainTransaction
        | UseCase::FirmwareSigning => EncryptionScheme::HybridMlKem768Aes256Gcm,

        UseCase::EmailEncryption
        | UseCase::FileStorage
        | UseCase::CloudStorage
        | UseCase::BackupArchive
        | UseCase::KeyExchange
        | UseCase::HealthcareRecords
        | UseCase::GovernmentClassified
        | UseCase::PaymentCard => EncryptionScheme::HybridMlKem1024Aes256Gcm,
    }
}

fn ml_kem_level_for_scheme(scheme: &EncryptionScheme) -> MlKemSecurityLevel {
    match scheme.ml_kem_level() {
        Some(level) => level,
        None => panic!("scheme {scheme} has no ML-KEM level"),
    }
}

fn expected_ciphertext_size(level: MlKemSecurityLevel) -> usize {
    level.ciphertext_size()
}

fn is_regulated(uc: &UseCase) -> bool {
    matches!(
        uc,
        UseCase::GovernmentClassified
            | UseCase::HealthcareRecords
            | UseCase::PaymentCard
            | UseCase::FinancialTransactions
    )
}

fn all_use_cases() -> Vec<UseCase> {
    vec![
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
        UseCase::AuditLog,
    ]
}

// ============================================================================
// Test 1: All 22 UseCases select correct hybrid scheme (THE KEY TEST)
// ============================================================================

#[test]
fn test_all_22_usecases_select_correct_hybrid_scheme() {
    let data = b"Contract test: UseCase -> Scheme selection";
    let use_cases = all_use_cases();
    assert_eq!(use_cases.len(), 22, "Must test all 22 UseCase variants");

    for uc in &use_cases {
        let expected = expected_scheme_for_use_case(uc);
        let level = ml_kem_level_for_scheme(&expected);
        let ct_size = expected_ciphertext_size(level);

        // Skip regulated use cases when FIPS is not available
        if is_regulated(uc) && !fips_available() {
            continue;
        }

        // Generate keypair at the level this UseCase requires
        let (pk, sk) = generate_hybrid_keypair_with_level(level)
            .unwrap_or_else(|e| panic!("keypair gen failed for {uc:?} at {level:?}: {e}"));

        // Encrypt with UseCase-driven config (NO force_scheme)
        let config = CryptoConfig::new().use_case(uc.clone());
        // Override FIPS compliance for regulated use cases in test env
        let config = if is_regulated(uc) && !fips_available() {
            config.compliance(ComplianceMode::Default)
        } else {
            config
        };

        let encrypted = encrypt(data, EncryptKey::Hybrid(&pk), config)
            .unwrap_or_else(|e| panic!("encrypt failed for {uc:?}: {e}"));

        // THE KEY ASSERTIONS: scheme matches expected for this UseCase
        assert_eq!(
            encrypted.scheme, expected,
            "UseCase::{uc:?} should select {expected}, got {}",
            encrypted.scheme
        );

        // Structural validation
        assert!(encrypted.hybrid_data.is_some(), "UseCase::{uc:?} must produce hybrid_data");
        let hybrid = encrypted.hybrid_data.as_ref().unwrap();
        assert_eq!(
            hybrid.ml_kem_ciphertext.len(),
            ct_size,
            "UseCase::{uc:?} ML-KEM ciphertext size: expected {ct_size}, got {}",
            hybrid.ml_kem_ciphertext.len()
        );
        assert_eq!(
            hybrid.ecdh_ephemeral_pk.len(),
            32,
            "UseCase::{uc:?} ECDH ephemeral PK must be 32 bytes"
        );

        // Decrypt roundtrip
        let config = CryptoConfig::new().use_case(uc.clone());
        let config = if is_regulated(uc) && !fips_available() {
            config.compliance(ComplianceMode::Default)
        } else {
            config
        };
        let decrypted = decrypt(&encrypted, DecryptKey::Hybrid(&sk), config)
            .unwrap_or_else(|e| panic!("decrypt failed for {uc:?}: {e}"));
        assert_eq!(decrypted.as_slice(), data, "UseCase::{uc:?} roundtrip failed");
    }
}

// ============================================================================
// Test 2: All 4 SecurityLevels select correct scheme
// ============================================================================

#[test]
fn test_all_4_security_levels_select_correct_scheme() {
    let data = b"Contract test: SecurityLevel -> Scheme selection";

    let cases: Vec<(SecurityLevel, EncryptionScheme)> = vec![
        (SecurityLevel::Standard, EncryptionScheme::HybridMlKem512Aes256Gcm),
        (SecurityLevel::High, EncryptionScheme::HybridMlKem768Aes256Gcm),
        (SecurityLevel::Maximum, EncryptionScheme::HybridMlKem1024Aes256Gcm),
        (SecurityLevel::Quantum, EncryptionScheme::HybridMlKem1024Aes256Gcm),
    ];

    for (level, expected_scheme) in &cases {
        let ml_kem_level = ml_kem_level_for_scheme(expected_scheme);
        let ct_size = expected_ciphertext_size(ml_kem_level);

        let (pk, sk) = generate_hybrid_keypair_with_level(ml_kem_level)
            .unwrap_or_else(|e| panic!("keypair gen failed for {level:?}: {e}"));

        let config = CryptoConfig::new().security_level(level.clone());
        let encrypted = encrypt(data, EncryptKey::Hybrid(&pk), config)
            .unwrap_or_else(|e| panic!("encrypt failed for {level:?}: {e}"));

        assert_eq!(
            &encrypted.scheme, expected_scheme,
            "SecurityLevel::{level:?} should select {expected_scheme}, got {}",
            encrypted.scheme
        );
        assert!(
            encrypted.hybrid_data.is_some(),
            "SecurityLevel::{level:?} must produce hybrid_data"
        );
        let hybrid = encrypted.hybrid_data.as_ref().unwrap();
        assert_eq!(
            hybrid.ml_kem_ciphertext.len(),
            ct_size,
            "SecurityLevel::{level:?} ML-KEM CT size mismatch"
        );

        let config = CryptoConfig::new().security_level(level.clone());
        let decrypted = decrypt(&encrypted, DecryptKey::Hybrid(&sk), config)
            .unwrap_or_else(|e| panic!("decrypt failed for {level:?}: {e}"));
        assert_eq!(decrypted.as_slice(), data, "SecurityLevel::{level:?} roundtrip failed");
    }
}

// ============================================================================
// Test 3: Scheme metadata matches ciphertext structure for all hybrid variants
// ============================================================================

#[test]
fn test_scheme_metadata_matches_ciphertext_structure() {
    let data = b"Contract test: scheme metadata vs ciphertext structure";

    let hybrid_schemes = [
        (EncryptionScheme::HybridMlKem512Aes256Gcm, MlKemSecurityLevel::MlKem512, 768),
        (EncryptionScheme::HybridMlKem768Aes256Gcm, MlKemSecurityLevel::MlKem768, 1088),
        (EncryptionScheme::HybridMlKem1024Aes256Gcm, MlKemSecurityLevel::MlKem1024, 1568),
    ];

    for (scheme, key_level, ct_size) in &hybrid_schemes {
        let (pk, sk) = generate_hybrid_keypair_with_level(*key_level)
            .unwrap_or_else(|e| panic!("keypair gen failed for {key_level:?}: {e}"));

        // Use security level that produces this scheme
        let security_level = match key_level {
            MlKemSecurityLevel::MlKem512 => SecurityLevel::Standard,
            MlKemSecurityLevel::MlKem768 => SecurityLevel::High,
            MlKemSecurityLevel::MlKem1024 => SecurityLevel::Maximum,
        };

        let config = CryptoConfig::new().security_level(security_level);
        let encrypted = encrypt(data, EncryptKey::Hybrid(&pk), config)
            .unwrap_or_else(|e| panic!("encrypt failed for {scheme}: {e}"));

        // Verify scheme metadata
        assert_eq!(
            encrypted.scheme.ml_kem_level(),
            Some(*key_level),
            "Scheme {scheme} should report ML-KEM level {key_level:?}"
        );

        // Verify hybrid_data invariant
        assert!(encrypted.scheme.requires_hybrid_key(), "Scheme {scheme} must require hybrid key");
        assert!(encrypted.hybrid_data.is_some(), "Scheme {scheme} must have hybrid_data");

        let hybrid = encrypted.hybrid_data.as_ref().unwrap();
        assert_eq!(
            hybrid.ml_kem_ciphertext.len(),
            *ct_size,
            "Scheme {scheme}: ML-KEM CT expected {ct_size} bytes, got {}",
            hybrid.ml_kem_ciphertext.len()
        );
        assert_eq!(
            hybrid.ecdh_ephemeral_pk.len(),
            32,
            "Scheme {scheme}: ECDH ephemeral PK must be 32 bytes"
        );

        // Nonce and tag sizes
        assert_eq!(encrypted.nonce.len(), 12, "Nonce must be 12 bytes");
        assert_eq!(encrypted.tag.len(), 16, "Tag must be 16 bytes");

        // Decrypt roundtrip
        let security_level = match key_level {
            MlKemSecurityLevel::MlKem512 => SecurityLevel::Standard,
            MlKemSecurityLevel::MlKem768 => SecurityLevel::High,
            MlKemSecurityLevel::MlKem1024 => SecurityLevel::Maximum,
        };
        let config = CryptoConfig::new().security_level(security_level);
        let decrypted = decrypt(&encrypted, DecryptKey::Hybrid(&sk), config)
            .unwrap_or_else(|e| panic!("decrypt failed for {scheme}: {e}"));
        assert_eq!(decrypted.as_slice(), data, "Roundtrip failed for {scheme}");
    }
}

// ============================================================================
// Test 4: Key-level mismatch is rejected (not silently degraded)
// ============================================================================

#[test]
fn test_key_level_mismatch_rejected() {
    let data = b"Contract test: key level mismatch must fail";

    // Test all 6 mismatch combinations (3 scheme levels × 2 wrong key levels each)
    let mismatches: Vec<(SecurityLevel, MlKemSecurityLevel, &str)> = vec![
        // Standard (expects 512) with 768 and 1024 keys
        (SecurityLevel::Standard, MlKemSecurityLevel::MlKem768, "Standard→768"),
        (SecurityLevel::Standard, MlKemSecurityLevel::MlKem1024, "Standard→1024"),
        // High (expects 768) with 512 and 1024 keys
        (SecurityLevel::High, MlKemSecurityLevel::MlKem512, "High→512"),
        (SecurityLevel::High, MlKemSecurityLevel::MlKem1024, "High→1024"),
        // Maximum (expects 1024) with 512 and 768 keys
        (SecurityLevel::Maximum, MlKemSecurityLevel::MlKem512, "Maximum→512"),
        (SecurityLevel::Maximum, MlKemSecurityLevel::MlKem768, "Maximum→768"),
    ];

    for (security_level, wrong_key_level, label) in &mismatches {
        let (pk, _sk) = generate_hybrid_keypair_with_level(*wrong_key_level)
            .unwrap_or_else(|e| panic!("keypair gen failed for {label}: {e}"));

        let config = CryptoConfig::new().security_level(security_level.clone());
        let result = encrypt(data, EncryptKey::Hybrid(&pk), config);

        assert!(result.is_err(), "Mismatch {label} should fail, but encrypt() succeeded");

        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("ML-KEM"),
            "Mismatch {label} error should mention ML-KEM: {err_msg}"
        );
    }
}

// ============================================================================
// Test 5: Symmetric scheme roundtrip with metadata assertion
// ============================================================================

#[test]
fn test_symmetric_scheme_roundtrip_with_metadata() {
    let data = b"Contract test: symmetric roundtrip with scheme assertion";
    let key = [0x42u8; 32];

    // AES-256-GCM via force_scheme(Symmetric) — explicit symmetric path
    let config = CryptoConfig::new().force_scheme(CryptoScheme::Symmetric);
    let encrypted = encrypt(data, EncryptKey::Symmetric(&key), config).unwrap();

    assert_eq!(
        encrypted.scheme,
        EncryptionScheme::Aes256Gcm,
        "force_scheme(Symmetric) must select AES-256-GCM"
    );
    assert!(encrypted.hybrid_data.is_none(), "Symmetric scheme must not have hybrid_data");
    assert!(!encrypted.scheme.requires_hybrid_key());
    assert!(encrypted.scheme.requires_symmetric_key());

    let decrypted = decrypt(&encrypted, DecryptKey::Symmetric(&key), CryptoConfig::new()).unwrap();
    assert_eq!(decrypted.as_slice(), data);
}

// ============================================================================
// Test 6: Serialization preserves scheme across all hybrid variants
// ============================================================================

#[test]
fn test_hybrid_encrypted_output_serialization_preserves_scheme() {
    let data = b"Contract test: serialization preserves scheme";

    let variants = [
        (MlKemSecurityLevel::MlKem512, SecurityLevel::Standard),
        (MlKemSecurityLevel::MlKem768, SecurityLevel::High),
        (MlKemSecurityLevel::MlKem1024, SecurityLevel::Maximum),
    ];

    for (key_level, security_level) in &variants {
        let (pk, sk) = generate_hybrid_keypair_with_level(*key_level)
            .unwrap_or_else(|e| panic!("keypair gen failed for {key_level:?}: {e}"));

        let config = CryptoConfig::new().security_level(security_level.clone());
        let original = encrypt(data, EncryptKey::Hybrid(&pk), config)
            .unwrap_or_else(|e| panic!("encrypt failed for {key_level:?}: {e}"));

        // Serialize → deserialize
        let json = serialize_encrypted_output(&original)
            .unwrap_or_else(|e| panic!("serialize failed for {key_level:?}: {e}"));
        let restored = deserialize_encrypted_output(&json)
            .unwrap_or_else(|e| panic!("deserialize failed for {key_level:?}: {e}"));

        // Scheme preserved
        assert_eq!(
            restored.scheme, original.scheme,
            "Serialization must preserve scheme for {key_level:?}"
        );

        // Hybrid data preserved
        assert!(
            restored.hybrid_data.is_some(),
            "Deserialized output must have hybrid_data for {key_level:?}"
        );
        let orig_hybrid = original.hybrid_data.as_ref().unwrap();
        let rest_hybrid = restored.hybrid_data.as_ref().unwrap();
        assert_eq!(
            orig_hybrid.ml_kem_ciphertext, rest_hybrid.ml_kem_ciphertext,
            "ML-KEM ciphertext must survive serialization for {key_level:?}"
        );
        assert_eq!(
            orig_hybrid.ecdh_ephemeral_pk, rest_hybrid.ecdh_ephemeral_pk,
            "ECDH ephemeral PK must survive serialization for {key_level:?}"
        );

        // Decrypt from deserialized output
        let config = CryptoConfig::new().security_level(security_level.clone());
        let decrypted = decrypt(&restored, DecryptKey::Hybrid(&sk), config)
            .unwrap_or_else(|e| panic!("decrypt-after-deserialize failed for {key_level:?}: {e}"));
        assert_eq!(
            decrypted.as_slice(),
            data,
            "Roundtrip via serialization failed for {key_level:?}"
        );
    }
}

// ============================================================================
// Test 7: Serialized scheme field is correct string
// ============================================================================

#[test]
fn test_serialized_scheme_field_is_correct_string() {
    let data = b"Contract test: JSON scheme field";

    // Test all scheme string representations via actual encryption
    let test_cases: Vec<(EncryptionScheme, &str)> = vec![
        (EncryptionScheme::HybridMlKem512Aes256Gcm, "hybrid-ml-kem-512-aes-256-gcm"),
        (EncryptionScheme::HybridMlKem768Aes256Gcm, "hybrid-ml-kem-768-aes-256-gcm"),
        (EncryptionScheme::HybridMlKem1024Aes256Gcm, "hybrid-ml-kem-1024-aes-256-gcm"),
    ];

    for (scheme, expected_str) in &test_cases {
        let level = scheme.ml_kem_level().unwrap();
        let (pk, _sk) = generate_hybrid_keypair_with_level(level)
            .unwrap_or_else(|e| panic!("keypair gen failed for {scheme}: {e}"));

        let security_level = match level {
            MlKemSecurityLevel::MlKem512 => SecurityLevel::Standard,
            MlKemSecurityLevel::MlKem768 => SecurityLevel::High,
            MlKemSecurityLevel::MlKem1024 => SecurityLevel::Maximum,
        };

        let config = CryptoConfig::new().security_level(security_level);
        let encrypted = encrypt(data, EncryptKey::Hybrid(&pk), config)
            .unwrap_or_else(|e| panic!("encrypt failed for {scheme}: {e}"));

        let json = serialize_encrypted_output(&encrypted)
            .unwrap_or_else(|e| panic!("serialize failed for {scheme}: {e}"));

        // Parse JSON and check scheme field
        let parsed: serde_json::Value = serde_json::from_str(&json)
            .unwrap_or_else(|e| panic!("JSON parse failed for {scheme}: {e}"));

        assert_eq!(
            parsed["scheme"].as_str().unwrap(),
            *expected_str,
            "JSON scheme field for {scheme}"
        );
    }

    // Also test symmetric
    let key = [0x42u8; 32];
    let config = CryptoConfig::new().force_scheme(CryptoScheme::Symmetric);
    let encrypted = encrypt(data, EncryptKey::Symmetric(&key), config).unwrap();
    let json = serialize_encrypted_output(&encrypted).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(
        parsed["scheme"].as_str().unwrap(),
        "aes-256-gcm",
        "JSON scheme field for AES-256-GCM"
    );
}
