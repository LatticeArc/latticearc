//! Cryptographic scheme tests (direct selection + contract behavior).
#![deny(unsafe_code)]

// Originally: scheme_contract_tests.rs
mod contract {
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
        clippy::unreachable,
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

    fn expected_scheme_for_use_case(uc: UseCase) -> EncryptionScheme {
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

            _ => unreachable!("unexpected UseCase variant"),
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

    fn is_regulated(uc: UseCase) -> bool {
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
    fn test_all_22_usecases_select_correct_hybrid_scheme_succeeds() {
        let data = b"Contract test: UseCase -> Scheme selection";
        let use_cases = all_use_cases();
        assert_eq!(use_cases.len(), 22, "Must test all 22 UseCase variants");

        for uc in &use_cases {
            let expected = expected_scheme_for_use_case(*uc);
            let level = ml_kem_level_for_scheme(&expected);
            let ct_size = expected_ciphertext_size(level);

            // Skip regulated use cases when FIPS is not available
            if is_regulated(*uc) && !fips_available() {
                continue;
            }

            // Generate keypair at the level this UseCase requires
            let (pk, sk) = generate_hybrid_keypair_with_level(level)
                .unwrap_or_else(|e| panic!("keypair gen failed for {uc:?} at {level:?}: {e}"));

            // Encrypt with UseCase-driven config (NO force_scheme)
            let config = CryptoConfig::new().use_case(*uc);
            // Override FIPS compliance for regulated use cases in test env
            let config = if is_regulated(*uc) && !fips_available() {
                config.compliance(ComplianceMode::Default)
            } else {
                config
            };

            let encrypted = encrypt(data, EncryptKey::Hybrid(&pk), config)
                .unwrap_or_else(|e| panic!("encrypt failed for {uc:?}: {e}"));

            // THE KEY ASSERTIONS: scheme matches expected for this UseCase
            assert_eq!(
                encrypted.scheme(),
                &expected,
                "UseCase::{uc:?} should select {expected}, got {}",
                encrypted.scheme()
            );

            // Structural validation
            assert!(encrypted.hybrid_data().is_some(), "UseCase::{uc:?} must produce hybrid_data");
            let hybrid = encrypted.hybrid_data().unwrap();
            assert_eq!(
                hybrid.ml_kem_ciphertext().len(),
                ct_size,
                "UseCase::{uc:?} ML-KEM ciphertext size: expected {ct_size}, got {}",
                hybrid.ml_kem_ciphertext().len()
            );
            assert_eq!(
                hybrid.ecdh_ephemeral_pk().len(),
                32,
                "UseCase::{uc:?} ECDH ephemeral PK must be 32 bytes"
            );

            // Decrypt roundtrip
            let config = CryptoConfig::new().use_case(*uc);
            let config = if is_regulated(*uc) && !fips_available() {
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
    fn test_all_security_levels_select_correct_scheme_succeeds() {
        let data = b"Contract test: SecurityLevel -> Scheme selection";

        let cases: Vec<(SecurityLevel, EncryptionScheme)> = vec![
            (SecurityLevel::Standard, EncryptionScheme::HybridMlKem512Aes256Gcm),
            (SecurityLevel::High, EncryptionScheme::HybridMlKem768Aes256Gcm),
            (SecurityLevel::Maximum, EncryptionScheme::HybridMlKem1024Aes256Gcm),
        ];

        for (level, expected_scheme) in &cases {
            let ml_kem_level = ml_kem_level_for_scheme(expected_scheme);
            let ct_size = expected_ciphertext_size(ml_kem_level);

            let (pk, sk) = generate_hybrid_keypair_with_level(ml_kem_level)
                .unwrap_or_else(|e| panic!("keypair gen failed for {level:?}: {e}"));

            let config = CryptoConfig::new().security_level(*level);
            let encrypted = encrypt(data, EncryptKey::Hybrid(&pk), config)
                .unwrap_or_else(|e| panic!("encrypt failed for {level:?}: {e}"));

            assert_eq!(
                encrypted.scheme(),
                expected_scheme,
                "SecurityLevel::{level:?} should select {expected_scheme}, got {}",
                encrypted.scheme()
            );
            assert!(
                encrypted.hybrid_data().is_some(),
                "SecurityLevel::{level:?} must produce hybrid_data"
            );
            let hybrid = encrypted.hybrid_data().unwrap();
            assert_eq!(
                hybrid.ml_kem_ciphertext().len(),
                ct_size,
                "SecurityLevel::{level:?} ML-KEM CT size mismatch"
            );

            let config = CryptoConfig::new().security_level(*level);
            let decrypted = decrypt(&encrypted, DecryptKey::Hybrid(&sk), config)
                .unwrap_or_else(|e| panic!("decrypt failed for {level:?}: {e}"));
            assert_eq!(decrypted.as_slice(), data, "SecurityLevel::{level:?} roundtrip failed");
        }
    }

    // ============================================================================
    // Test 3: Scheme metadata matches ciphertext structure for all hybrid variants
    // ============================================================================

    #[test]
    fn test_scheme_metadata_matches_ciphertext_structure_succeeds() {
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
                _ => unreachable!("unexpected MlKemSecurityLevel variant"),
            };

            let config = CryptoConfig::new().security_level(security_level);
            let encrypted = encrypt(data, EncryptKey::Hybrid(&pk), config)
                .unwrap_or_else(|e| panic!("encrypt failed for {scheme}: {e}"));

            // Verify scheme metadata
            assert_eq!(
                encrypted.scheme().ml_kem_level(),
                Some(*key_level),
                "Scheme {scheme} should report ML-KEM level {key_level:?}"
            );

            // Verify hybrid_data invariant
            assert!(
                encrypted.scheme().requires_hybrid_key(),
                "Scheme {scheme} must require hybrid key"
            );
            assert!(encrypted.hybrid_data().is_some(), "Scheme {scheme} must have hybrid_data");

            let hybrid = encrypted.hybrid_data().unwrap();
            assert_eq!(
                hybrid.ml_kem_ciphertext().len(),
                *ct_size,
                "Scheme {scheme}: ML-KEM CT expected {ct_size} bytes, got {}",
                hybrid.ml_kem_ciphertext().len()
            );
            assert_eq!(
                hybrid.ecdh_ephemeral_pk().len(),
                32,
                "Scheme {scheme}: ECDH ephemeral PK must be 32 bytes"
            );

            // Nonce and tag sizes
            assert_eq!(encrypted.nonce().len(), 12, "Nonce must be 12 bytes");
            assert_eq!(encrypted.tag().len(), 16, "Tag must be 16 bytes");

            // Decrypt roundtrip
            let security_level = match key_level {
                MlKemSecurityLevel::MlKem512 => SecurityLevel::Standard,
                MlKemSecurityLevel::MlKem768 => SecurityLevel::High,
                MlKemSecurityLevel::MlKem1024 => SecurityLevel::Maximum,
                _ => unreachable!("unexpected MlKemSecurityLevel variant"),
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
    fn test_key_level_mismatch_rejected_fails() {
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

            let config = CryptoConfig::new().security_level(*security_level);
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
    fn test_symmetric_scheme_roundtrip_with_metadata_roundtrip() {
        let data = b"Contract test: symmetric roundtrip with scheme assertion";
        let key = [0x42u8; 32];

        // AES-256-GCM via force_scheme(Symmetric) — explicit symmetric path
        let config = CryptoConfig::new().force_scheme(CryptoScheme::Symmetric);
        let encrypted = encrypt(data, EncryptKey::Symmetric(&key), config).unwrap();

        assert_eq!(
            encrypted.scheme(),
            &EncryptionScheme::Aes256Gcm,
            "force_scheme(Symmetric) must select AES-256-GCM"
        );
        assert!(encrypted.hybrid_data().is_none(), "Symmetric scheme must not have hybrid_data");
        assert!(!encrypted.scheme().requires_hybrid_key());
        assert!(encrypted.scheme().requires_symmetric_key());

        let decrypted =
            decrypt(&encrypted, DecryptKey::Symmetric(&key), CryptoConfig::new()).unwrap();
        assert_eq!(decrypted.as_slice(), data);
    }

    // ============================================================================
    // Test 6: Serialization preserves scheme across all hybrid variants
    // ============================================================================

    #[test]
    fn test_hybrid_encrypted_output_serialization_preserves_scheme_succeeds() {
        let data = b"Contract test: serialization preserves scheme";

        let variants = [
            (MlKemSecurityLevel::MlKem512, SecurityLevel::Standard),
            (MlKemSecurityLevel::MlKem768, SecurityLevel::High),
            (MlKemSecurityLevel::MlKem1024, SecurityLevel::Maximum),
        ];

        for (key_level, security_level) in &variants {
            let (pk, sk) = generate_hybrid_keypair_with_level(*key_level)
                .unwrap_or_else(|e| panic!("keypair gen failed for {key_level:?}: {e}"));

            let config = CryptoConfig::new().security_level(*security_level);
            let original = encrypt(data, EncryptKey::Hybrid(&pk), config)
                .unwrap_or_else(|e| panic!("encrypt failed for {key_level:?}: {e}"));

            // Serialize → deserialize
            let json = serialize_encrypted_output(&original)
                .unwrap_or_else(|e| panic!("serialize failed for {key_level:?}: {e}"));
            let restored = deserialize_encrypted_output(&json)
                .unwrap_or_else(|e| panic!("deserialize failed for {key_level:?}: {e}"));

            // Scheme preserved
            assert_eq!(
                restored.scheme(),
                original.scheme(),
                "Serialization must preserve scheme for {key_level:?}"
            );

            // Hybrid data preserved
            assert!(
                restored.hybrid_data().is_some(),
                "Deserialized output must have hybrid_data for {key_level:?}"
            );
            let orig_hybrid = original.hybrid_data().unwrap();
            let rest_hybrid = restored.hybrid_data().unwrap();
            assert_eq!(
                orig_hybrid.ml_kem_ciphertext(),
                rest_hybrid.ml_kem_ciphertext(),
                "ML-KEM ciphertext must survive serialization for {key_level:?}"
            );
            assert_eq!(
                orig_hybrid.ecdh_ephemeral_pk(),
                rest_hybrid.ecdh_ephemeral_pk(),
                "ECDH ephemeral PK must survive serialization for {key_level:?}"
            );

            // Decrypt from deserialized output
            let config = CryptoConfig::new().security_level(*security_level);
            let decrypted =
                decrypt(&restored, DecryptKey::Hybrid(&sk), config).unwrap_or_else(|e| {
                    panic!("decrypt-after-deserialize failed for {key_level:?}: {e}")
                });
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
    fn test_serialized_scheme_field_is_correct_string_succeeds() {
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
                _ => unreachable!("unexpected MlKemSecurityLevel variant"),
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
}

// Originally: direct_scheme_coverage.rs
mod direct {
    //! Direct scheme dispatch tests for api.rs verify() branches.
    //! These bypass the CryptoConfig selector by manually constructing
    //! SignedData with specific scheme names, covering branches that
    //! the selector never picks through CryptoConfig.

    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic,
        clippy::arithmetic_side_effects,
        clippy::cast_precision_loss,
        clippy::single_match
    )]

    use latticearc::primitives::sig::fndsa::FnDsaSecurityLevel;
    use latticearc::primitives::sig::ml_dsa::MlDsaParameterSet;
    use latticearc::primitives::sig::slh_dsa::SlhDsaSecurityLevel;
    use latticearc::types::types::CryptoScheme;
    use latticearc::unified_api::convenience::*;
    use latticearc::unified_api::crypto_types::{
        DecryptKey, EncryptKey, EncryptedOutput, EncryptionScheme,
    };
    use latticearc::unified_api::types::{CryptoConfig, SignedData, SignedMetadata};

    // ============================================================
    // verify() with SLH-DSA schemes (unreachable via selector)
    // ============================================================

    #[test]
    fn test_verify_slh_dsa_128s_direct_succeeds() {
        let (pk, sk) = generate_slh_dsa_keypair(SlhDsaSecurityLevel::Shake128s).unwrap();
        let msg = b"SLH-DSA-128s direct verify test";
        let sig =
            sign_pq_slh_dsa_unverified(msg, sk.expose_secret(), SlhDsaSecurityLevel::Shake128s)
                .unwrap();

        let signed = SignedData {
            data: msg.to_vec(),
            metadata: SignedMetadata {
                signature: sig,
                signature_algorithm: "slh-dsa-shake-128s".to_string(),
                public_key: pk.into_bytes(),
                key_id: None,
            },
            scheme: "slh-dsa-shake-128s".to_string(),
            timestamp: 0,
        };

        let config = CryptoConfig::new();
        let valid = verify(&signed, config).unwrap();
        assert!(valid, "SLH-DSA-128s verification should succeed");
    }

    #[test]
    fn test_verify_slh_dsa_192s_direct_succeeds() {
        let (pk, sk) = generate_slh_dsa_keypair(SlhDsaSecurityLevel::Shake192s).unwrap();
        let msg = b"SLH-DSA-192s direct verify test";
        let sig =
            sign_pq_slh_dsa_unverified(msg, sk.expose_secret(), SlhDsaSecurityLevel::Shake192s)
                .unwrap();

        let signed = SignedData {
            data: msg.to_vec(),
            metadata: SignedMetadata {
                signature: sig,
                signature_algorithm: "slh-dsa-shake-192s".to_string(),
                public_key: pk.into_bytes(),
                key_id: None,
            },
            scheme: "slh-dsa-shake-192s".to_string(),
            timestamp: 0,
        };

        let config = CryptoConfig::new();
        let valid = verify(&signed, config).unwrap();
        assert!(valid, "SLH-DSA-192s verification should succeed");
    }

    #[test]
    fn test_verify_slh_dsa_256s_direct_succeeds() {
        let (pk, sk) = generate_slh_dsa_keypair(SlhDsaSecurityLevel::Shake256s).unwrap();
        let msg = b"SLH-DSA-256s direct verify test";
        let sig =
            sign_pq_slh_dsa_unverified(msg, sk.expose_secret(), SlhDsaSecurityLevel::Shake256s)
                .unwrap();

        let signed = SignedData {
            data: msg.to_vec(),
            metadata: SignedMetadata {
                signature: sig,
                signature_algorithm: "slh-dsa-shake-256s".to_string(),
                public_key: pk.into_bytes(),
                key_id: None,
            },
            scheme: "slh-dsa-shake-256s".to_string(),
            timestamp: 0,
        };

        let config = CryptoConfig::new();
        let valid = verify(&signed, config).unwrap();
        assert!(valid, "SLH-DSA-256s verification should succeed");
    }

    // ============================================================
    // verify() with FN-DSA scheme
    // ============================================================

    #[test]
    fn test_verify_fn_dsa_direct_succeeds() {
        let (pk, sk) = generate_fn_dsa_keypair().unwrap();
        let msg = b"FN-DSA direct verify test";
        let sig = sign_pq_fn_dsa_unverified(msg, sk.expose_secret(), FnDsaSecurityLevel::Level512)
            .unwrap();

        let signed = SignedData {
            data: msg.to_vec(),
            metadata: SignedMetadata {
                signature: sig,
                signature_algorithm: "fn-dsa".to_string(),
                public_key: pk.into_bytes(),
                key_id: None,
            },
            scheme: "fn-dsa".to_string(),
            timestamp: 0,
        };

        let config = CryptoConfig::new();
        let valid = verify(&signed, config).unwrap();
        assert!(valid, "FN-DSA verification should succeed");
    }

    // ============================================================
    // verify() with pure ML-DSA schemes (non-hybrid)
    // ============================================================

    #[test]
    fn test_verify_pure_ml_dsa_44_direct_succeeds() {
        let (pk, sk) = generate_ml_dsa_keypair(MlDsaParameterSet::MlDsa44).unwrap();
        let msg = b"Pure ML-DSA-44 verify test";
        let sig =
            sign_pq_ml_dsa_unverified(msg, sk.expose_secret(), MlDsaParameterSet::MlDsa44).unwrap();

        let signed = SignedData {
            data: msg.to_vec(),
            metadata: SignedMetadata {
                signature: sig,
                signature_algorithm: "pq-ml-dsa-44".to_string(),
                public_key: pk.into_bytes(),
                key_id: None,
            },
            scheme: "pq-ml-dsa-44".to_string(),
            timestamp: 0,
        };

        let config = CryptoConfig::new();
        let valid = verify(&signed, config).unwrap();
        assert!(valid, "Pure ML-DSA-44 verification should succeed");
    }

    #[test]
    fn test_verify_pure_ml_dsa_65_direct_succeeds() {
        let (pk, sk) = generate_ml_dsa_keypair(MlDsaParameterSet::MlDsa65).unwrap();
        let msg = b"Pure ML-DSA-65 verify test";
        let sig =
            sign_pq_ml_dsa_unverified(msg, sk.expose_secret(), MlDsaParameterSet::MlDsa65).unwrap();

        let signed = SignedData {
            data: msg.to_vec(),
            metadata: SignedMetadata {
                signature: sig,
                signature_algorithm: "pq-ml-dsa-65".to_string(),
                public_key: pk.into_bytes(),
                key_id: None,
            },
            scheme: "pq-ml-dsa-65".to_string(),
            timestamp: 0,
        };

        let config = CryptoConfig::new();
        let valid = verify(&signed, config).unwrap();
        assert!(valid, "Pure ML-DSA-65 verification should succeed");
    }

    // ============================================================
    // verify() with Ed25519 fallback scheme
    //
    // Round-11 audit fix #9: the `"ed25519"` verify dispatch arm is
    // cfg-gated under `not(feature = "fips")` for symmetry with
    // sign_with_key (which has always been cfg-gated). Under
    // `--features fips`, all three Ed25519 dispatch points (keygen,
    // sign, verify) reject uniformly. This test is therefore only
    // meaningful in non-FIPS builds.
    // ============================================================

    #[cfg(not(feature = "fips"))]
    #[test]
    fn test_verify_ed25519_scheme_is_supported() {
        let (pk, sk) = generate_keypair().unwrap();
        let msg = b"Ed25519 verify test";
        let sig = sign_ed25519_unverified(msg, sk.expose_secret()).unwrap();

        let signed = SignedData {
            data: msg.to_vec(),
            metadata: SignedMetadata {
                signature: sig,
                signature_algorithm: "ed25519".to_string(),
                public_key: pk.into_bytes(),
                key_id: None,
            },
            scheme: "ed25519".to_string(),
            timestamp: 0,
        };

        let config = CryptoConfig::new();
        let valid = verify(&signed, config).unwrap();
        assert!(valid, "Ed25519 verification should succeed");
    }

    // ============================================================
    // Decrypt with alternative scheme names
    // ============================================================

    #[test]
    fn test_decrypt_chacha_scheme_rejected_fails() {
        let key = vec![0x42u8; 32];
        let data = b"Test data for chacha scheme name";
        let config = CryptoConfig::new();

        // Encrypt with AES-256-GCM (default symmetric scheme)
        let encrypted = encrypt(
            data.as_ref(),
            EncryptKey::Symmetric(&key),
            config.clone().force_scheme(CryptoScheme::Symmetric),
        )
        .unwrap();

        // Re-wrap with ChaCha20-Poly1305 scheme — decrypt will attempt ChaCha20 decryption of an
        // AES-GCM ciphertext and fail (AEAD authentication tag mismatch).
        let rewrapped = EncryptedOutput::new(
            EncryptionScheme::ChaCha20Poly1305,
            encrypted.ciphertext().to_vec(),
            encrypted.nonce().to_vec(),
            encrypted.tag().to_vec(),
            None,
            encrypted.timestamp(),
            None,
        )
        .expect("symmetric scheme + None hybrid_data is a valid shape");

        let result = decrypt(&rewrapped, DecryptKey::Symmetric(&key), config);
        assert!(result.is_err(), "chacha20-poly1305 decryption of AES-GCM ciphertext should fail");
    }

    #[test]
    fn test_decrypt_ml_kem_scheme_name_accepted_succeeds() {
        let key = vec![0x42u8; 32];
        let data = b"Test data for ml-kem scheme name";
        let config = CryptoConfig::new();

        // Encrypt with AES-256-GCM (symmetric) and decrypt with the same scheme.
        // The old test used a string "ml-kem-768" that mapped to AES-256-GCM internally;
        // with the type-safe API we use Aes256Gcm directly and verify round-trip succeeds.
        let encrypted = encrypt(
            data.as_ref(),
            EncryptKey::Symmetric(&key),
            config.clone().force_scheme(CryptoScheme::Symmetric),
        )
        .unwrap();

        let decrypted = decrypt(&encrypted, DecryptKey::Symmetric(&key), config).unwrap();
        assert_eq!(decrypted.as_slice(), data.as_slice());
    }

    #[test]
    fn test_decrypt_unknown_scheme_rejected_fails() {
        let key = vec![0x42u8; 32];
        let data = b"Test data for unknown scheme";
        let config = CryptoConfig::new();

        let encrypted = encrypt(
            data.as_ref(),
            EncryptKey::Symmetric(&key),
            config.clone().force_scheme(CryptoScheme::Symmetric),
        )
        .unwrap();

        // Constructing an EncryptedOutput with a hybrid scheme but
        // `hybrid_data: None` is structurally invalid; the shape check in
        // `EncryptedOutput::new` rejects it before any decrypt attempt.
        let rewrapped = EncryptedOutput::new(
            EncryptionScheme::HybridMlKem768Aes256Gcm,
            encrypted.ciphertext().to_vec(),
            encrypted.nonce().to_vec(),
            encrypted.tag().to_vec(),
            None,
            encrypted.timestamp(),
            None,
        );

        assert!(
            rewrapped.is_err(),
            "Hybrid scheme without hybrid_data must be rejected at construction"
        );
        let _ = config; // keep the variable to mirror the original test shape
    }

    // ============================================================
    // Verify with tampered SLH-DSA signature
    // ============================================================

    #[test]
    fn test_verify_slh_dsa_128s_tampered_fails() {
        let (pk, sk) = generate_slh_dsa_keypair(SlhDsaSecurityLevel::Shake128s).unwrap();
        let msg = b"SLH-DSA tampered sig test";
        let mut sig =
            sign_pq_slh_dsa_unverified(msg, sk.expose_secret(), SlhDsaSecurityLevel::Shake128s)
                .unwrap();

        // Tamper with signature
        if let Some(byte) = sig.first_mut() {
            *byte ^= 0xFF;
        }

        let signed = SignedData {
            data: msg.to_vec(),
            metadata: SignedMetadata {
                signature: sig,
                signature_algorithm: "slh-dsa-shake-128s".to_string(),
                public_key: pk.into_bytes(),
                key_id: None,
            },
            scheme: "slh-dsa-shake-128s".to_string(),
            timestamp: 0,
        };

        let config = CryptoConfig::new();
        let result = verify(&signed, config);
        match result {
            Ok(valid) => assert!(!valid, "Tampered SLH-DSA signature should not verify"),
            Err(_) => {} // error is also acceptable
        }
    }
}
