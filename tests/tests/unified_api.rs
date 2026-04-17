//! unified_api integration tests (encrypt/decrypt/sign/verify via the public facade).
//!
//! Sub-modules preserve original file structure.
#![deny(unsafe_code)]

// Originally: unified_api_comprehensive.rs
mod comprehensive {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]
    #![allow(clippy::indexing_slicing)]
    #![allow(missing_docs)]
    //! Comprehensive Unified API Integration Tests
    //!
    //! Exercises `latticearc::encrypt()` / `latticearc::decrypt()` through the public
    //! facade with ALL 22 UseCases and ALL 4 SecurityLevels.
    //!
    //! Run with: `cargo test --package latticearc --test unified_api_comprehensive --all-features --release`

    use latticearc::{
        ComplianceMode, CryptoConfig, CryptoScheme, DecryptKey, EncryptKey, EncryptedData,
        EncryptedOutput, EncryptionScheme, SecurityLevel, UseCase, decrypt, encrypt,
        fips_available, generate_hybrid_keypair, generate_signing_keypair, sign_with_key, verify,
    };

    // ============================================================================
    // KNOWN GAPS — Tests that SHOULD pass but CAN'T due to upstream blockers.
    //
    // Each #[ignore] test documents a known limitation. The test body describes what
    // would be tested and why it cannot run. Run with `--include-ignored` to see
    // the full list.
    // ============================================================================

    /// The unified `encrypt()`/`decrypt()` API uses AES-256-GCM with symmetric keys.
    /// The `&[u8]` key interface cannot carry ML-KEM/X25519 typed keys, so KEM is
    /// not possible through this API. This is by design.
    ///
    /// For true PQ encryption, use `encrypt_hybrid()` with typed `HybridPublicKey`.
    #[test]
    fn test_unified_api_uses_aes256gcm_by_design_succeeds() {
        let key = [0x42u8; 32];
        let data = b"test data for unified API";

        // Even with Maximum+PqOnly security level and GovernmentClassified use case,
        // the unified API correctly uses AES-256-GCM (symmetric key path).
        let config = CryptoConfig::new()
            .security_level(SecurityLevel::Maximum)
            .crypto_mode(latticearc::CryptoMode::PqOnly)
            .use_case(UseCase::GovernmentClassified);
        // Override auto-FIPS when feature not available (test verifies AES-GCM selection, not FIPS)
        let config =
            if fips_available() { config } else { config.compliance(ComplianceMode::Default) };

        let encrypted = encrypt(
            data,
            EncryptKey::Symmetric(&key),
            config.clone().force_scheme(CryptoScheme::Symmetric),
        )
        .expect("encrypt should succeed");

        // The effective scheme is AES-256-GCM (not ML-KEM), which is correct
        // because the unified API receives a symmetric key.
        assert_eq!(
            encrypted.scheme(),
            &EncryptionScheme::Aes256Gcm,
            "Unified API with symmetric key should use AES-256-GCM"
        );

        let decrypted = decrypt(&encrypted, DecryptKey::Symmetric(&key), config)
            .expect("decrypt should succeed");
        assert_eq!(decrypted.as_slice(), data.as_slice());
    }

    /// ML-KEM standalone decapsulation requires a live `DecapsulationKey` object.
    ///
    /// ML-KEM standalone decapsulation round-trip via serialized secret key.
    #[test]
    fn test_ml_kem_standalone_decapsulation_succeeds() {
        use latticearc::primitives::kem::ml_kem::{MlKem, MlKemSecurityLevel};
        let (pk, sk) =
            MlKem::generate_keypair(MlKemSecurityLevel::MlKem768).expect("keygen should succeed");
        let (ss_enc, ct) = MlKem::encapsulate(&pk).expect("encapsulate should succeed");
        let ss_dec = MlKem::decapsulate(&sk, &ct).expect("decapsulate should succeed");
        assert_eq!(ss_enc.as_bytes(), ss_dec.as_bytes(), "shared secrets must match");
    }

    /// Hybrid signing keygen uses Ed25519 `generate_keypair()` from
    /// `arc-core::convenience::keygen`.
    #[test]
    fn test_hybrid_signing_keygen_is_correct() {
        let config = CryptoConfig::new().security_level(SecurityLevel::High);
        let (pk, sk, scheme) =
            generate_signing_keypair(config.clone()).expect("hybrid signing keygen should succeed");

        assert!(
            scheme.contains("hybrid") || scheme.contains("ed25519") || scheme.contains("pq-ml-dsa"),
            "Scheme should be hybrid, ed25519, or pq-ml-dsa, got: {scheme}"
        );
        assert!(!pk.is_empty(), "Public key should not be empty");
        assert!(!sk.is_empty(), "Secret key should not be empty");

        // Verify the keypair actually works for sign + verify roundtrip
        let message = b"test message for hybrid signing";
        let signed =
            sign_with_key(message, &sk, &pk, config.clone()).expect("signing should succeed");
        let valid = verify(&signed, config).expect("verification should succeed");
        assert!(valid, "Signature from hybrid keygen should verify");
    }

    /// Maximum + PqOnly signing selects PQ-only ML-DSA-87 (no Ed25519 hybrid).
    ///
    /// Uses the `fips204` crate for ML-DSA. This crate is not FIPS-validated
    /// (unlike aws-lc-rs). Excluded to flag as a known migration point.
    #[test]
    #[ignore = "ML-DSA uses fips204 crate which is not FIPS-validated"]
    fn test_sign_verify_pq_only_maximum_level_succeeds() {
        let config = CryptoConfig::new()
            .security_level(SecurityLevel::Maximum)
            .crypto_mode(latticearc::CryptoMode::PqOnly);
        let (pk, sk, scheme) = generate_signing_keypair(config.clone()).expect("keygen");
        assert_eq!(scheme, "pq-ml-dsa-87");

        let signed = sign_with_key(b"pq-only test", &sk, &pk, config).expect("sign");
        let valid = verify(&signed, CryptoConfig::new()).expect("verify");
        assert!(valid, "PQ-only ML-DSA-87 signature should verify");
    }

    /// ML-KEM secret key persistence: serialize, deserialize, and decapsulate.
    #[test]
    fn test_ml_kem_key_persistence_succeeds() {
        use latticearc::primitives::kem::ml_kem::{
            MlKem, MlKemPublicKey, MlKemSecretKey, MlKemSecurityLevel,
        };

        let (pk, sk) =
            MlKem::generate_keypair(MlKemSecurityLevel::MlKem768).expect("keygen should succeed");

        // Serialize both keys
        let pk_bytes = pk.as_bytes().to_vec();
        let sk_bytes = sk.as_bytes().to_vec();

        // Restore from bytes
        let pk2 = MlKemPublicKey::from_bytes(&pk_bytes, MlKemSecurityLevel::MlKem768)
            .expect("pk restore should succeed");
        let sk2 = MlKemSecretKey::new(MlKemSecurityLevel::MlKem768, sk_bytes)
            .expect("sk restore should succeed");

        // Encapsulate with restored PK, decapsulate with restored SK
        let (ss_enc, ct) = MlKem::encapsulate(&pk2).expect("encapsulate should succeed");
        let ss_dec = MlKem::decapsulate(&sk2, &ct).expect("decapsulate should succeed");
        assert_eq!(
            ss_enc.as_bytes(),
            ss_dec.as_bytes(),
            "round-trip through serialization must match"
        );
    }

    // ============================================================================
    // Unified encrypt/decrypt — All 24 UseCases
    // ============================================================================

    fn all_use_cases() -> Vec<UseCase> {
        vec![
            // Communication (4)
            UseCase::SecureMessaging,
            UseCase::EmailEncryption,
            UseCase::VpnTunnel,
            UseCase::ApiSecurity,
            // Storage (5)
            UseCase::FileStorage,
            UseCase::DatabaseEncryption,
            UseCase::CloudStorage,
            UseCase::BackupArchive,
            UseCase::ConfigSecrets,
            // Authentication & Identity (4)
            UseCase::Authentication,
            UseCase::SessionToken,
            UseCase::DigitalCertificate,
            UseCase::KeyExchange,
            // Financial & Legal (3)
            UseCase::FinancialTransactions,
            UseCase::LegalDocuments,
            UseCase::BlockchainTransaction,
            // Regulated Industries (3)
            UseCase::HealthcareRecords,
            UseCase::GovernmentClassified,
            UseCase::PaymentCard,
            // IoT & Embedded (2)
            UseCase::IoTDevice,
            UseCase::FirmwareSigning,
            UseCase::AuditLog,
        ]
    }

    #[test]
    fn test_symmetric_encrypt_decrypt_across_all_22_use_cases_roundtrip() {
        let key = [0x42u8; 32];
        let plaintext = b"Unified API roundtrip for every UseCase";
        let use_cases = all_use_cases();
        assert_eq!(use_cases.len(), 22, "Expected 22 use cases");

        for uc in &use_cases {
            let config = CryptoConfig::new().use_case(*uc);

            // Regulated use cases require FIPS; skip roundtrip when feature unavailable
            let is_regulated = matches!(
                uc,
                UseCase::GovernmentClassified
                    | UseCase::HealthcareRecords
                    | UseCase::PaymentCard
                    | UseCase::FinancialTransactions
            );
            if is_regulated && !fips_available() {
                let result = encrypt(
                    plaintext,
                    EncryptKey::Symmetric(&key),
                    config.force_scheme(CryptoScheme::Symmetric),
                );
                assert!(result.is_err(), "Regulated {:?} should fail without FIPS", uc);
                continue;
            }

            let encrypted = encrypt(
                plaintext,
                EncryptKey::Symmetric(&key),
                config.force_scheme(CryptoScheme::Symmetric),
            )
            .unwrap_or_else(|e| panic!("encrypt failed for {:?}: {}", uc, e));

            assert!(!encrypted.scheme().as_str().is_empty(), "{:?} scheme should be set", uc);
            assert!(!encrypted.ciphertext().is_empty(), "{:?} ciphertext should be non-empty", uc);

            let decrypted = decrypt(&encrypted, DecryptKey::Symmetric(&key), CryptoConfig::new())
                .unwrap_or_else(|e| panic!("decrypt failed for {:?}: {}", uc, e));
            assert_eq!(decrypted.as_slice(), plaintext, "Roundtrip mismatch for {:?}", uc);
        }
    }

    // ============================================================================
    // Unified encrypt/decrypt — All 4 SecurityLevels
    // ============================================================================

    #[test]
    fn test_symmetric_encrypt_decrypt_across_all_security_levels_roundtrip() {
        let key = [0x55u8; 32];
        let plaintext = b"Unified API roundtrip for every SecurityLevel";

        let levels = [SecurityLevel::Standard, SecurityLevel::High, SecurityLevel::Maximum];

        for level in &levels {
            let config = CryptoConfig::new().security_level(*level);
            let encrypted = encrypt(
                plaintext,
                EncryptKey::Symmetric(&key),
                config.force_scheme(CryptoScheme::Symmetric),
            )
            .unwrap_or_else(|e| panic!("encrypt failed for {:?}: {}", level, e));

            assert!(!encrypted.scheme().as_str().is_empty(), "{:?} scheme should be set", level);

            let decrypted = decrypt(&encrypted, DecryptKey::Symmetric(&key), CryptoConfig::new())
                .unwrap_or_else(|e| panic!("decrypt failed for {:?}: {}", level, e));
            assert_eq!(decrypted.as_slice(), plaintext, "Roundtrip mismatch for {:?}", level);
        }
    }

    // ============================================================================
    // Default CryptoConfig roundtrip
    // ============================================================================

    #[test]
    fn test_encrypt_decrypt_default_config_roundtrip() {
        let key = [0xAAu8; 32];
        let plaintext = b"Default CryptoConfig roundtrip through facade";

        let encrypted = encrypt(
            plaintext,
            EncryptKey::Symmetric(&key),
            CryptoConfig::new().force_scheme(CryptoScheme::Symmetric),
        )
        .expect("default encrypt should succeed");
        let decrypted = decrypt(&encrypted, DecryptKey::Symmetric(&key), CryptoConfig::new())
            .expect("default decrypt should succeed");

        assert_eq!(decrypted.as_slice(), plaintext);
    }

    // ============================================================================
    // Empty and large plaintext
    // ============================================================================

    #[test]
    fn test_encrypt_decrypt_empty_plaintext_roundtrip() {
        let key = [0xBBu8; 32];
        let plaintext = b"";

        let encrypted = encrypt(
            plaintext,
            EncryptKey::Symmetric(&key),
            CryptoConfig::new().force_scheme(CryptoScheme::Symmetric),
        )
        .expect("encrypt empty should succeed");
        let decrypted = decrypt(&encrypted, DecryptKey::Symmetric(&key), CryptoConfig::new())
            .expect("decrypt empty should succeed");

        assert_eq!(decrypted.as_slice(), plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_large_plaintext_roundtrip() {
        let key = [0xCCu8; 32];
        let plaintext = vec![0xFFu8; 64 * 1024]; // 64 KiB

        let encrypted = encrypt(
            &plaintext,
            EncryptKey::Symmetric(&key),
            CryptoConfig::new().force_scheme(CryptoScheme::Symmetric),
        )
        .expect("encrypt large should succeed");
        let decrypted = decrypt(&encrypted, DecryptKey::Symmetric(&key), CryptoConfig::new())
            .expect("decrypt large should succeed");

        assert_eq!(decrypted.as_slice(), plaintext.as_slice());
    }

    // ============================================================================
    // Nonce uniqueness — same plaintext encrypts differently
    // ============================================================================

    #[test]
    fn test_encrypt_nonce_uniqueness_produces_different_ciphertext_are_unique() {
        let key = [0xDDu8; 32];
        let plaintext = b"Same plaintext encrypted twice";

        let enc1 = encrypt(
            plaintext,
            EncryptKey::Symmetric(&key),
            CryptoConfig::new().force_scheme(CryptoScheme::Symmetric),
        )
        .expect("encrypt 1");
        let enc2 = encrypt(
            plaintext,
            EncryptKey::Symmetric(&key),
            CryptoConfig::new().force_scheme(CryptoScheme::Symmetric),
        )
        .expect("encrypt 2");

        assert_ne!(
            enc1.ciphertext(),
            enc2.ciphertext(),
            "Random nonces should produce different ciphertexts"
        );
    }

    // ============================================================================
    // Key rejection
    // ============================================================================

    #[test]
    fn test_encrypt_rejects_short_key_fails() {
        let short_key = [0x42u8; 16];
        let result = encrypt(
            b"data",
            EncryptKey::Symmetric(&short_key),
            CryptoConfig::new().force_scheme(CryptoScheme::Symmetric),
        );
        assert!(result.is_err(), "16-byte key should be rejected");
    }

    #[test]
    fn test_decrypt_wrong_key_fails() {
        let key = [0x42u8; 32];
        let wrong_key = [0x99u8; 32];
        let plaintext = b"Wrong key should fail decryption";

        let encrypted = encrypt(
            plaintext,
            EncryptKey::Symmetric(&key),
            CryptoConfig::new().force_scheme(CryptoScheme::Symmetric),
        )
        .expect("encrypt");
        let result = decrypt(&encrypted, DecryptKey::Symmetric(&wrong_key), CryptoConfig::new());
        assert!(result.is_err(), "Decryption with wrong key should fail");
    }

    // ============================================================================
    // Tamper detection
    // ============================================================================

    #[test]
    fn test_decrypt_tampered_ciphertext_fails() {
        let key = [0x42u8; 32];
        let plaintext = b"Tamper detection through unified API";

        let encrypted = encrypt(
            plaintext,
            EncryptKey::Symmetric(&key),
            CryptoConfig::new().force_scheme(CryptoScheme::Symmetric),
        )
        .expect("encrypt");

        // Convert to legacy type to mutate the ciphertext, then convert back
        let mut legacy_data = EncryptedData::from(encrypted);
        if legacy_data.data.len() > 12 {
            legacy_data.data[12] ^= 0xFF;
        }
        let tampered =
            EncryptedOutput::try_from(legacy_data).expect("conversion back to EncryptedOutput");

        let result = decrypt(&tampered, DecryptKey::Symmetric(&key), CryptoConfig::new());
        assert!(result.is_err(), "Tampered ciphertext should fail");
    }

    // ============================================================================
    // Sign/Verify — All 4 SecurityLevels through facade
    // ============================================================================

    #[test]
    fn test_sign_verify_all_security_levels_succeeds() {
        let message = b"Sign/verify at every security level through facade";

        for level in [SecurityLevel::Standard, SecurityLevel::High, SecurityLevel::Maximum] {
            let config = CryptoConfig::new().security_level(level);
            let (pk, sk, scheme) = generate_signing_keypair(config)
                .unwrap_or_else(|e| panic!("keygen {:?}: {}", level, e));
            assert!(!scheme.is_empty());

            let config = CryptoConfig::new().security_level(level);
            let signed = sign_with_key(message, &sk, &pk, config)
                .unwrap_or_else(|e| panic!("sign {:?}: {}", level, e));

            let is_valid = verify(&signed, CryptoConfig::new())
                .unwrap_or_else(|e| panic!("verify {:?}: {}", level, e));
            assert!(is_valid, "Signature should verify at {:?}", level);
        }
    }

    // ============================================================================
    // Hybrid encrypt/decrypt through facade
    // ============================================================================

    #[test]
    fn test_hybrid_encrypt_decrypt_through_facade_roundtrip() {
        let (pk, sk) = generate_hybrid_keypair().expect("keygen");
        let plaintext = b"Hybrid ML-KEM-768 + X25519 through latticearc facade";

        let encrypted =
            encrypt(plaintext, EncryptKey::Hybrid(&pk), CryptoConfig::new()).expect("encrypt");
        let hybrid = encrypted.hybrid_data().expect("should have hybrid_data");
        assert_eq!(hybrid.ml_kem_ciphertext().len(), 1088);
        assert_eq!(hybrid.ecdh_ephemeral_pk().len(), 32);

        let decrypted =
            decrypt(&encrypted, DecryptKey::Hybrid(&sk), CryptoConfig::new()).expect("decrypt");
        assert_eq!(decrypted.as_slice(), plaintext);
    }

    #[test]
    fn test_hybrid_wrong_key_fails() {
        let (pk1, _sk1) = generate_hybrid_keypair().expect("keygen 1");
        let (_pk2, sk2) = generate_hybrid_keypair().expect("keygen 2");

        let encrypted =
            encrypt(b"data", EncryptKey::Hybrid(&pk1), CryptoConfig::new()).expect("encrypt");
        let result = decrypt(&encrypted, DecryptKey::Hybrid(&sk2), CryptoConfig::new());
        assert!(result.is_err(), "Decrypt with wrong hybrid key should fail");
    }

    // ============================================================================
    // Complete workflow: derive key → encrypt → sign → verify → decrypt
    // ============================================================================

    #[test]
    fn test_complete_encrypt_sign_verify_decrypt_workflow_succeeds() {
        // Step 1: Encrypt
        let key = [0x42u8; 32];
        let plaintext = b"Complete workflow through facade";
        let encrypted = encrypt(
            plaintext,
            EncryptKey::Symmetric(&key),
            CryptoConfig::new().force_scheme(CryptoScheme::Symmetric),
        )
        .expect("encrypt");

        // Step 2: Sign the ciphertext
        let config = CryptoConfig::new().security_level(SecurityLevel::High);
        let (sign_pk, sign_sk, _) = generate_signing_keypair(config).expect("keygen");

        let config = CryptoConfig::new().security_level(SecurityLevel::High);
        let signed =
            sign_with_key(encrypted.ciphertext(), &sign_sk, &sign_pk, config).expect("sign");

        // Step 3: Verify
        let is_valid = verify(&signed, CryptoConfig::new()).expect("verify");
        assert!(is_valid);

        // Step 4: Decrypt
        let decrypted =
            decrypt(&encrypted, DecryptKey::Symmetric(&key), CryptoConfig::new()).expect("decrypt");
        assert_eq!(decrypted.as_slice(), plaintext);
    }
}

// Originally: unified_api_coverage.rs
mod coverage {
    //! Coverage tests for the unified encrypt/decrypt/sign_with_key/verify API
    //! in arc-core/src/convenience/api.rs. Exercises different CryptoConfig
    //! selections (UseCase, SecurityLevel) to hit uncovered scheme branches.

    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic,
        clippy::arithmetic_side_effects,
        clippy::cast_precision_loss,
        clippy::single_match,
        clippy::redundant_clone
    )]

    use latticearc::unified_api::convenience::*;
    use latticearc::unified_api::types::{CryptoConfig, SecurityLevel, UseCase};
    use latticearc::{ComplianceMode, CryptoScheme, DecryptKey, EncryptKey, fips_available};

    // ============================================================
    // encrypt() with different CryptoConfig selections
    // ============================================================

    #[test]
    fn test_encrypt_default_config_succeeds() {
        let key = vec![0x42u8; 32];
        let data = b"Test data for default config";
        let config = CryptoConfig::new();

        let encrypted = encrypt(
            data.as_ref(),
            EncryptKey::Symmetric(key.as_ref()),
            config.force_scheme(CryptoScheme::Symmetric),
        )
        .unwrap();
        assert!(!encrypted.ciphertext().is_empty());
        assert!(!encrypted.scheme().as_str().is_empty());
    }

    #[test]
    fn test_encrypt_use_case_file_storage_succeeds() {
        let key = vec![0x42u8; 32];
        let data = b"File storage encryption test";
        let config = CryptoConfig::new().use_case(UseCase::FileStorage);

        let encrypted = encrypt(
            data.as_ref(),
            EncryptKey::Symmetric(key.as_ref()),
            config.force_scheme(CryptoScheme::Symmetric),
        )
        .unwrap();
        assert!(!encrypted.ciphertext().is_empty());
    }

    #[test]
    fn test_encrypt_use_case_secure_messaging_succeeds() {
        let key = vec![0x42u8; 32];
        let data = b"Secure messaging encryption test";
        let config = CryptoConfig::new().use_case(UseCase::SecureMessaging);

        let encrypted = encrypt(
            data.as_ref(),
            EncryptKey::Symmetric(key.as_ref()),
            config.force_scheme(CryptoScheme::Symmetric),
        )
        .unwrap();
        assert!(!encrypted.ciphertext().is_empty());
    }

    #[test]
    fn test_encrypt_use_case_iot_device_succeeds() {
        let key = vec![0x42u8; 32];
        let data = b"IoT device encryption test";
        let config = CryptoConfig::new().use_case(UseCase::IoTDevice);

        let encrypted = encrypt(
            data.as_ref(),
            EncryptKey::Symmetric(key.as_ref()),
            config.force_scheme(CryptoScheme::Symmetric),
        )
        .unwrap();
        assert!(!encrypted.ciphertext().is_empty());
    }

    #[test]
    fn test_encrypt_security_level_maximum_succeeds() {
        let key = vec![0x42u8; 32];
        let data = b"Maximum security level encryption";
        let config = CryptoConfig::new().security_level(SecurityLevel::Maximum);

        let encrypted = encrypt(
            data.as_ref(),
            EncryptKey::Symmetric(key.as_ref()),
            config.force_scheme(CryptoScheme::Symmetric),
        )
        .unwrap();
        assert!(!encrypted.ciphertext().is_empty());
    }

    #[test]
    fn test_encrypt_security_level_standard_succeeds() {
        let key = vec![0x42u8; 32];
        let data = b"Standard security level encryption";
        let config = CryptoConfig::new().security_level(SecurityLevel::Standard);

        let encrypted = encrypt(
            data.as_ref(),
            EncryptKey::Symmetric(key.as_ref()),
            config.force_scheme(CryptoScheme::Symmetric),
        )
        .unwrap();
        assert!(!encrypted.ciphertext().is_empty());
    }

    #[test]
    fn test_encrypt_security_level_high_succeeds() {
        let key = vec![0x42u8; 32];
        let data = b"High security level encryption";
        let config = CryptoConfig::new().security_level(SecurityLevel::High);

        let encrypted = encrypt(
            data.as_ref(),
            EncryptKey::Symmetric(key.as_ref()),
            config.force_scheme(CryptoScheme::Symmetric),
        )
        .unwrap();
        assert!(!encrypted.ciphertext().is_empty());
    }

    #[test]
    fn test_encrypt_invalid_key_too_short_fails() {
        let short_key = vec![0x42u8; 10];
        let data = b"test data";
        let config = CryptoConfig::new();

        let result = encrypt(
            data.as_ref(),
            EncryptKey::Symmetric(short_key.as_ref()),
            config.force_scheme(CryptoScheme::Symmetric),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypt_empty_data_succeeds() {
        let key = vec![0x42u8; 32];
        let data = b"";
        let config = CryptoConfig::new();

        let encrypted = encrypt(
            data.as_ref(),
            EncryptKey::Symmetric(key.as_ref()),
            config.force_scheme(CryptoScheme::Symmetric),
        )
        .unwrap();
        // AES-GCM produces nonce+tag even for empty plaintext
        assert!(!encrypted.ciphertext().is_empty());
    }

    // ============================================================
    // decrypt() with different scheme names
    // ============================================================

    #[test]
    fn test_encrypt_decrypt_roundtrip_default_succeeds() {
        let key = vec![0x42u8; 32];
        let data = b"Roundtrip test data with default config";
        let config = CryptoConfig::new();

        let encrypted = encrypt(
            data.as_ref(),
            EncryptKey::Symmetric(key.as_ref()),
            config.clone().force_scheme(CryptoScheme::Symmetric),
        )
        .unwrap();
        let decrypted = decrypt(&encrypted, DecryptKey::Symmetric(&key), config).unwrap();
        assert_eq!(decrypted.as_slice(), data.as_slice());
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip_file_storage_succeeds() {
        let key = vec![0x42u8; 32];
        let data = b"File storage roundtrip";
        let config = CryptoConfig::new().use_case(UseCase::FileStorage);

        let encrypted = encrypt(
            data.as_ref(),
            EncryptKey::Symmetric(key.as_ref()),
            config.clone().force_scheme(CryptoScheme::Symmetric),
        )
        .unwrap();
        let decrypted = decrypt(&encrypted, DecryptKey::Symmetric(&key), config).unwrap();
        assert_eq!(decrypted.as_slice(), data.as_slice());
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip_iot_succeeds() {
        let key = vec![0x42u8; 32];
        let data = b"IoT device roundtrip";
        let config = CryptoConfig::new().use_case(UseCase::IoTDevice);

        let encrypted = encrypt(
            data.as_ref(),
            EncryptKey::Symmetric(key.as_ref()),
            config.clone().force_scheme(CryptoScheme::Symmetric),
        )
        .unwrap();
        let decrypted = decrypt(&encrypted, DecryptKey::Symmetric(&key), config).unwrap();
        assert_eq!(decrypted.as_slice(), data.as_slice());
    }

    #[test]
    fn test_decrypt_empty_data_succeeds() {
        let key = vec![0x42u8; 32];
        let config = CryptoConfig::new();

        let encrypted = encrypt(
            b"",
            EncryptKey::Symmetric(key.as_ref()),
            config.clone().force_scheme(CryptoScheme::Symmetric),
        )
        .unwrap();
        let decrypted = decrypt(&encrypted, DecryptKey::Symmetric(&key), config).unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn test_decrypt_invalid_key_too_short_fails() {
        let key = vec![0x42u8; 32];
        let short_key = vec![0x42u8; 10];
        let data = b"test";
        let config = CryptoConfig::new();

        let encrypted = encrypt(
            data.as_ref(),
            EncryptKey::Symmetric(key.as_ref()),
            config.clone().force_scheme(CryptoScheme::Symmetric),
        )
        .unwrap();
        let result = decrypt(&encrypted, DecryptKey::Symmetric(&short_key), config);
        assert!(result.is_err());
    }

    // ============================================================
    // generate_signing_keypair() + sign_with_key() + verify()
    // for various schemes
    // ============================================================

    #[test]
    fn test_sign_verify_authentication_use_case_keypair_succeeds() {
        // Authentication use case maps to a signing scheme (hybrid-ml-dsa)
        let config = CryptoConfig::new().use_case(UseCase::Authentication);
        let (pk, sk, scheme) = generate_signing_keypair(config.clone()).unwrap();
        assert!(!pk.is_empty());
        assert!(!sk.is_empty());

        let message = b"Authentication sign/verify test";
        let signed = sign_with_key(message, &sk, &pk, config.clone()).unwrap();
        let valid = verify(&signed, config).unwrap();
        assert!(valid, "Scheme {} should verify correctly", scheme);
    }

    #[test]
    fn test_sign_verify_iot_use_case_succeeds() {
        // `IoTDevice` is a resource-constrained use case, not a category that
        // bans signing. `UseCaseConfig::new(IoTDevice)` assigns
        // `SecurityLevel::Standard`, so signing keygen returns
        // `hybrid-ml-dsa-44-ed25519` (L1 hybrid).
        let config = CryptoConfig::new().use_case(UseCase::IoTDevice);
        let (pk, sk, scheme) = generate_signing_keypair(config.clone()).unwrap();
        assert_eq!(scheme, "hybrid-ml-dsa-44-ed25519");

        let message = b"IoT use case sign/verify test";
        let signed = sign_with_key(message, &sk, &pk, config.clone()).unwrap();
        assert!(verify(&signed, config).unwrap(), "signature must verify");
    }

    #[test]
    fn test_sign_verify_default_scheme_succeeds() {
        let config = CryptoConfig::new();
        let (pk, sk, scheme) = generate_signing_keypair(config.clone()).unwrap();

        let message = b"Default scheme sign/verify test";
        let signed = sign_with_key(message, &sk, &pk, config.clone()).unwrap();
        let valid = verify(&signed, config).unwrap();
        assert!(valid, "Default scheme {} should verify", scheme);
    }

    #[test]
    fn test_sign_verify_maximum_security_succeeds() {
        let config = CryptoConfig::new().security_level(SecurityLevel::Maximum);
        let (pk, sk, scheme) = generate_signing_keypair(config.clone()).unwrap();

        let message = b"Maximum security sign test";
        let signed = sign_with_key(message, &sk, &pk, config.clone()).unwrap();
        let valid = verify(&signed, config).unwrap();
        assert!(valid, "Max security scheme {} should verify", scheme);
    }

    #[test]
    fn test_sign_verify_standard_security_succeeds() {
        let config = CryptoConfig::new().security_level(SecurityLevel::Standard);
        let (pk, sk, scheme) = generate_signing_keypair(config.clone()).unwrap();

        let message = b"Standard security sign test";
        let signed = sign_with_key(message, &sk, &pk, config.clone()).unwrap();
        let valid = verify(&signed, config).unwrap();
        assert!(valid, "Standard security scheme {} should verify", scheme);
    }

    #[test]
    fn test_sign_verify_file_storage_use_case_succeeds() {
        // `FileStorage` is a long-term-security use case → `SecurityLevel::Maximum`
        // → the L5 hybrid signing scheme. The policy engine routes the encryption
        // scheme selector only for encryption operations; signing keygen pulls the
        // security level from `UseCaseConfig` instead.
        let config = CryptoConfig::new().use_case(UseCase::FileStorage);
        let (pk, sk, scheme) = generate_signing_keypair(config.clone()).unwrap();
        assert_eq!(scheme, "hybrid-ml-dsa-87-ed25519");

        let message = b"FileStorage use case sign/verify test";
        let signed = sign_with_key(message, &sk, &pk, config.clone()).unwrap();
        assert!(verify(&signed, config).unwrap(), "signature must verify");
    }

    #[test]
    fn test_sign_verify_secure_messaging_use_case_succeeds() {
        // `SecureMessaging` uses the `UseCaseConfig` default security level
        // (`SecurityLevel::High`), which selects the L3 hybrid signing scheme.
        let config = CryptoConfig::new().use_case(UseCase::SecureMessaging);
        let (pk, sk, scheme) = generate_signing_keypair(config.clone()).unwrap();
        assert_eq!(scheme, "hybrid-ml-dsa-65-ed25519");

        let message = b"SecureMessaging use case sign/verify test";
        let signed = sign_with_key(message, &sk, &pk, config.clone()).unwrap();
        assert!(verify(&signed, config).unwrap(), "signature must verify");
    }

    // ============================================================
    // PQ-only (Maximum + PqOnly) security level
    // ============================================================

    #[test]
    fn test_sign_verify_pq_only_maximum_succeeds() {
        let config = CryptoConfig::new()
            .security_level(SecurityLevel::Maximum)
            .crypto_mode(latticearc::CryptoMode::PqOnly);
        let (pk, sk, scheme) = generate_signing_keypair(config.clone()).unwrap();
        assert!(
            scheme.contains("ml-dsa") || scheme.contains("pq-ml-dsa"),
            "PQ-only Maximum should use pure ML-DSA, got: {}",
            scheme
        );

        let message = b"PQ-only Maximum security sign test";
        let signed = sign_with_key(message, &sk, &pk, config.clone()).unwrap();
        let valid = verify(&signed, config).unwrap();
        assert!(valid, "PQ-only scheme {} should verify", scheme);
    }

    #[test]
    fn test_encrypt_security_level_pq_only_maximum_succeeds() {
        let key = vec![0x42u8; 32];
        let data = b"PQ-only Maximum security level encryption";
        let config = CryptoConfig::new()
            .security_level(SecurityLevel::Maximum)
            .crypto_mode(latticearc::CryptoMode::PqOnly);

        let encrypted = encrypt(
            data.as_ref(),
            EncryptKey::Symmetric(key.as_ref()),
            config.clone().force_scheme(CryptoScheme::Symmetric),
        )
        .unwrap();
        assert!(!encrypted.ciphertext().is_empty());
        let decrypted = decrypt(&encrypted, DecryptKey::Symmetric(&key), config).unwrap();
        assert_eq!(decrypted.as_slice(), data.as_slice());
    }

    // ============================================================
    // UseCase-based signing (hits Ed25519 fallback for KEM use cases)
    // ============================================================

    #[test]
    fn test_sign_verify_authentication_use_case_succeeds() {
        let config = CryptoConfig::new().use_case(UseCase::Authentication);
        let (pk, sk, scheme) = generate_signing_keypair(config.clone()).unwrap();

        let message = b"Authentication signing test";
        let signed = sign_with_key(message, &sk, &pk, config.clone()).unwrap();
        let valid = verify(&signed, config).unwrap();
        assert!(valid, "Authentication scheme {} should verify", scheme);
    }

    #[test]
    fn test_sign_verify_financial_use_case_succeeds() {
        let config = CryptoConfig::new().use_case(UseCase::FinancialTransactions);
        // Override auto-FIPS only when feature not available (test verifies signing, not FIPS)
        let config =
            if fips_available() { config } else { config.compliance(ComplianceMode::Default) };
        let (pk, sk, scheme) = generate_signing_keypair(config.clone()).unwrap();

        let message = b"Financial transaction signing test";
        let signed = sign_with_key(message, &sk, &pk, config.clone()).unwrap();
        let valid = verify(&signed, config).unwrap();
        assert!(valid, "Financial scheme {} should verify", scheme);
    }

    // ============================================================
    // init() and self_tests_passed()
    // ============================================================

    #[test]
    fn test_unified_api_init_succeeds() {
        let result = latticearc::unified_api::init();
        assert!(result.is_ok(), "init() should succeed");
    }

    #[test]
    fn test_unified_api_init_with_default_config_succeeds() {
        let config = latticearc::unified_api::CoreConfig::default();
        let result = latticearc::unified_api::init_with_config(&config);
        assert!(result.is_ok(), "init_with_config(default) should succeed");
    }

    #[test]
    fn test_self_tests_passed_after_init_succeeds() {
        // Run init first to ensure self-tests have run
        let _ = latticearc::unified_api::init();
        assert!(
            latticearc::unified_api::self_tests_passed(),
            "Self-tests should have passed after init"
        );
    }

    #[test]
    fn test_version_string_is_nonempty_succeeds() {
        assert!(!latticearc::unified_api::VERSION.is_empty(), "VERSION should not be empty");
    }

    // ============================================================
    // Error paths in verify
    // ============================================================

    #[test]
    fn test_verify_with_wrong_signature_fails() {
        let config = CryptoConfig::new().use_case(UseCase::Authentication);
        let (pk, sk, _scheme) = generate_signing_keypair(config.clone()).unwrap();

        let message = b"Original message";
        let mut signed = sign_with_key(message, &sk, &pk, config.clone()).unwrap();

        // Tamper with the signature
        if let Some(byte) = signed.metadata.signature.first_mut() {
            *byte ^= 0xFF;
        }

        // Verification should fail (return false or error)
        let result = verify(&signed, config);
        match result {
            Ok(valid) => assert!(!valid, "Tampered signature should not verify"),
            Err(_) => {} // Error is also acceptable for invalid signatures
        }
    }

    #[test]
    fn test_verify_with_wrong_message_fails() {
        let config = CryptoConfig::new().use_case(UseCase::Authentication);
        let (pk, sk, _scheme) = generate_signing_keypair(config.clone()).unwrap();

        let message = b"Original message";
        let mut signed = sign_with_key(message, &sk, &pk, config.clone()).unwrap();

        // Change the message
        signed.data = b"Tampered message".to_vec();

        let result = verify(&signed, config);
        match result {
            Ok(valid) => assert!(!valid, "Wrong message should not verify"),
            Err(_) => {}
        }
    }

    // ============================================================
    // Hybrid signature key length error paths
    // ============================================================

    #[test]
    fn test_sign_hybrid_44_sk_wrong_length_fails() {
        // Generate hybrid-44 keypair: uses IoTDevice which maps to ml-dsa-44 or hybrid-44
        let config = CryptoConfig::new().security_level(SecurityLevel::Standard);
        let (pk, sk, scheme) = generate_signing_keypair(config.clone()).unwrap();

        // Only test if scheme is hybrid
        if scheme.contains("hybrid") {
            // Truncate sk to trigger wrong length error
            let short_sk = &sk[..sk.len() / 2];
            let result = sign_with_key(b"test", short_sk, &pk, config);
            assert!(result.is_err(), "Truncated hybrid sk should fail: scheme={}", scheme);
        }
    }

    #[test]
    fn test_sign_hybrid_pk_wrong_length_fails() {
        let config = CryptoConfig::new().security_level(SecurityLevel::Standard);
        let (_pk, sk, scheme) = generate_signing_keypair(config.clone()).unwrap();

        if scheme.contains("hybrid") {
            // Pass a short pk
            let short_pk = vec![0u8; 10];
            let result = sign_with_key(b"test", &sk, &short_pk, config);
            assert!(result.is_err(), "Short hybrid pk should fail: scheme={}", scheme);
        }
    }

    #[test]
    fn test_sign_hybrid_65_sk_wrong_length_fails() {
        let config = CryptoConfig::new().security_level(SecurityLevel::High);
        let (pk, sk, scheme) = generate_signing_keypair(config.clone()).unwrap();

        if scheme.contains("hybrid") {
            let short_sk = &sk[..sk.len() / 2];
            let result = sign_with_key(b"test", short_sk, &pk, config);
            assert!(result.is_err(), "Truncated hybrid-65 sk should fail: scheme={}", scheme);
        }
    }

    #[test]
    fn test_sign_hybrid_87_sk_wrong_length_fails() {
        let config = CryptoConfig::new().security_level(SecurityLevel::Maximum);
        let (pk, sk, scheme) = generate_signing_keypair(config.clone()).unwrap();

        if scheme.contains("hybrid") {
            let short_sk = &sk[..sk.len() / 2];
            let result = sign_with_key(b"test", short_sk, &pk, config);
            assert!(result.is_err(), "Truncated hybrid-87 sk should fail: scheme={}", scheme);
        }
    }

    #[test]
    fn test_sign_hybrid_87_pk_wrong_length_fails() {
        let config = CryptoConfig::new().security_level(SecurityLevel::Maximum);
        let (_pk, sk, scheme) = generate_signing_keypair(config.clone()).unwrap();

        if scheme.contains("hybrid") {
            let short_pk = vec![0u8; 10];
            let result = sign_with_key(b"test", &sk, &short_pk, config);
            assert!(result.is_err(), "Short hybrid-87 pk should fail: scheme={}", scheme);
        }
    }

    // ============================================================
    // PQ-only scheme branches (pq-ml-dsa-*)
    // ============================================================

    #[test]
    fn test_verify_pq_ml_dsa_44_scheme_succeeds() {
        let config = CryptoConfig::new()
            .security_level(SecurityLevel::Standard)
            .crypto_mode(latticearc::CryptoMode::PqOnly);
        let (pk, sk, _scheme) = generate_signing_keypair(config.clone()).unwrap();

        let message = b"PQ-only ML-DSA-44 verification test";
        let mut signed = sign_with_key(message, &sk, &pk, config.clone()).unwrap();

        if signed.scheme.contains("ml-dsa-44") || signed.scheme.contains("pq-ml-dsa-44") {
            signed.scheme = "pq-ml-dsa-44".to_string();
            let result = verify(&signed, config);
            match result {
                Ok(valid) => assert!(valid, "pq-ml-dsa-44 should verify with correct keys"),
                Err(e) => panic!("Unexpected error verifying pq-ml-dsa-44: {}", e),
            }
        }
    }

    #[test]
    fn test_verify_pq_ml_dsa_65_scheme_succeeds() {
        let config = CryptoConfig::new()
            .security_level(SecurityLevel::High)
            .crypto_mode(latticearc::CryptoMode::PqOnly);
        let (pk, sk, _scheme) = generate_signing_keypair(config.clone()).unwrap();

        let message = b"PQ-only ML-DSA-65 verification test";
        let mut signed = sign_with_key(message, &sk, &pk, config.clone()).unwrap();

        if signed.scheme.contains("ml-dsa-65") || signed.scheme.contains("pq-ml-dsa-65") {
            signed.scheme = "pq-ml-dsa-65".to_string();
            let result = verify(&signed, config);
            match result {
                Ok(valid) => assert!(valid, "pq-ml-dsa-65 should verify with correct keys"),
                Err(e) => panic!("Unexpected error verifying pq-ml-dsa-65: {}", e),
            }
        }
    }

    #[test]
    fn test_verify_pq_ml_dsa_87_scheme_succeeds() {
        let config = CryptoConfig::new()
            .security_level(SecurityLevel::Maximum)
            .crypto_mode(latticearc::CryptoMode::PqOnly);
        let (pk, sk, scheme) = generate_signing_keypair(config.clone()).unwrap();

        assert!(
            scheme.contains("ml-dsa-87"),
            "Maximum+PqOnly should select ml-dsa-87 variant, got: {scheme}"
        );

        let message = b"ML-DSA-87 verification test";
        let signed = sign_with_key(message, &sk, &pk, config.clone()).unwrap();
        let valid = verify(&signed, config).unwrap();
        assert!(valid, "Signature should verify");
    }

    // ============================================================
    // Sign with ml-dsa-87 variant via Maximum + PqOnly
    // ============================================================

    #[test]
    fn test_sign_with_key_pq_ml_dsa_scheme_succeeds() {
        let config = CryptoConfig::new()
            .security_level(SecurityLevel::Maximum)
            .crypto_mode(latticearc::CryptoMode::PqOnly);
        let (pk, sk, scheme) = generate_signing_keypair(config.clone()).unwrap();

        assert!(scheme.contains("ml-dsa-87"), "Maximum+PqOnly should use ML-DSA-87, got: {scheme}");

        let message = b"PQ-only Maximum security level signing";
        let signed = sign_with_key(message, &sk, &pk, config.clone()).unwrap();
        let valid = verify(&signed, config).unwrap();
        assert!(valid, "Scheme {scheme} should verify correctly");
    }
}

// Originally: unified_api_integration.rs
mod integration {
    //! Unified API integration tests for LatticeArc
    //!
    //! These tests verify that the LatticeArc unified API works correctly
    //! for real-world use cases including encryption, hashing, HMAC,
    //! and key derivation.

    #![allow(clippy::expect_used)]
    #![allow(clippy::indexing_slicing)]

    use latticearc::{
        SecurityMode, decrypt_aes_gcm, derive_key, encrypt_aes_gcm, hash_data, hmac, hmac_check,
    };

    // ============================================================================
    // Basic Symmetric Encryption Tests (AES-GCM)
    // ============================================================================

    #[test]
    fn test_aes_gcm_roundtrip() {
        let plaintext = b"Sensitive data that needs protection";
        let key = [0x42u8; 32]; // AES-256 key

        let ciphertext = encrypt_aes_gcm(plaintext, &key, SecurityMode::Unverified)
            .expect("encryption should succeed");

        // Ciphertext should be plaintext + nonce(12) + tag(16) = plaintext + 28 bytes
        assert!(ciphertext.len() > plaintext.len(), "Ciphertext should be longer than plaintext");

        let decrypted = decrypt_aes_gcm(&ciphertext, &key, SecurityMode::Unverified)
            .expect("decryption should succeed");

        assert_eq!(decrypted.as_slice(), plaintext, "Roundtrip should preserve plaintext");
    }

    #[test]
    fn test_aes_gcm_different_keys_produce_different_ciphertext_succeeds() {
        let plaintext = b"Test data";
        let key1 = [0x41u8; 32];
        let key2 = [0x42u8; 32];

        let ct1 = encrypt_aes_gcm(plaintext, &key1, SecurityMode::Unverified)
            .expect("encryption should succeed");
        let ct2 = encrypt_aes_gcm(plaintext, &key2, SecurityMode::Unverified)
            .expect("encryption should succeed");

        // Even with random nonces, different keys produce different ciphertexts
        assert_ne!(ct1, ct2, "Different keys should produce different ciphertexts");
    }

    #[test]
    fn test_aes_gcm_random_nonces_produce_different_ciphertext_succeeds() {
        let plaintext = b"Test data";
        let key = [0x42u8; 32];

        let ct1 = encrypt_aes_gcm(plaintext, &key, SecurityMode::Unverified)
            .expect("encryption should succeed");
        let ct2 = encrypt_aes_gcm(plaintext, &key, SecurityMode::Unverified)
            .expect("encryption should succeed");

        // Random nonces should make ciphertexts different
        assert_ne!(ct1, ct2, "Random nonces should produce different ciphertexts");
    }

    #[test]
    fn test_aes_gcm_wrong_key_fails_decryption_fails() {
        let plaintext = b"Test data";
        let key_enc = [0x41u8; 32];
        let key_dec = [0x42u8; 32];

        let ciphertext = encrypt_aes_gcm(plaintext, &key_enc, SecurityMode::Unverified)
            .expect("encryption should succeed");
        let result = decrypt_aes_gcm(&ciphertext, &key_dec, SecurityMode::Unverified);

        assert!(result.is_err(), "Wrong key should fail decryption");
    }

    #[test]
    fn test_aes_gcm_tampered_ciphertext_fails() {
        let plaintext = b"Test data";
        let key = [0x42u8; 32];

        let mut ciphertext = encrypt_aes_gcm(plaintext, &key, SecurityMode::Unverified)
            .expect("encryption should succeed");

        // Tamper with ciphertext (after the nonce)
        if ciphertext.len() > 12 {
            ciphertext[12] ^= 0xFF;
        }

        let result = decrypt_aes_gcm(&ciphertext, &key, SecurityMode::Unverified);
        assert!(result.is_err(), "Tampered ciphertext should fail authentication");
    }

    #[test]
    fn test_aes_gcm_empty_plaintext_roundtrip() {
        let plaintext = b"";
        let key = [0x42u8; 32];

        let ciphertext = encrypt_aes_gcm(plaintext, &key, SecurityMode::Unverified)
            .expect("encryption should succeed");
        let decrypted = decrypt_aes_gcm(&ciphertext, &key, SecurityMode::Unverified)
            .expect("decryption should succeed");

        assert!(decrypted.is_empty(), "Empty plaintext should decrypt to empty");
    }

    #[test]
    fn test_aes_gcm_key_too_short_fails() {
        let plaintext = b"Test data";
        let short_key = [0x42u8; 16]; // AES-128 key (too short for this API)

        let result = encrypt_aes_gcm(plaintext, &short_key, SecurityMode::Unverified);
        assert!(result.is_err(), "Short key should fail");
    }

    // ============================================================================
    // Hashing Tests
    // ============================================================================

    #[test]
    fn test_hash_deterministic_produces_same_output_is_deterministic() {
        let data = b"Data to hash";

        let hash1 = hash_data(data);
        let hash2 = hash_data(data);

        assert_eq!(hash1, hash2, "Same data should produce same hash");
    }

    #[test]
    fn test_hash_different_inputs_produce_different_output_succeeds() {
        let data1 = b"First data";
        let data2 = b"Second data";

        let hash1 = hash_data(data1);
        let hash2 = hash_data(data2);

        assert_ne!(hash1, hash2, "Different data should produce different hashes");
    }

    #[test]
    fn test_hash_empty_input_has_correct_length_fails() {
        let empty = b"";
        let hash = hash_data(empty);
        // SHA-3-256 produces 32-byte output even for empty input
        assert_eq!(hash.len(), 32, "Hash should be 32 bytes");
    }

    #[test]
    fn test_hash_large_input_has_correct_length_has_correct_size() {
        let large_data = vec![0x42u8; 1_000_000]; // 1MB
        let hash = hash_data(&large_data);
        assert_eq!(hash.len(), 32, "Hash should be 32 bytes");
    }

    #[test]
    fn test_hash_output_size_is_32_bytes_has_correct_size() {
        let data = b"Test data";
        let hash = hash_data(data);

        // SHA-3-256 produces 32-byte output
        assert_eq!(hash.len(), 32, "Hash should be 32 bytes");
    }

    // ============================================================================
    // HMAC Tests
    // ============================================================================

    #[test]
    fn test_hmac_roundtrip() {
        let message = b"Message to authenticate";
        let key = b"secret key for hmac";

        let tag = hmac(message, key, SecurityMode::Unverified).expect("HMAC should succeed");
        let is_valid = hmac_check(message, key, &tag, SecurityMode::Unverified)
            .expect("HMAC verify should succeed");

        assert!(is_valid, "Valid HMAC should verify");
    }

    #[test]
    fn test_hmac_wrong_key_fails_verification_fails() {
        let message = b"Message to authenticate";
        let key1 = b"correct key";
        let key2 = b"wrong key";

        let tag = hmac(message, key1, SecurityMode::Unverified).expect("HMAC should succeed");
        let is_valid = hmac_check(message, key2, &tag, SecurityMode::Unverified)
            .expect("HMAC verify should succeed");

        assert!(!is_valid, "Wrong key should fail HMAC verification");
    }

    #[test]
    fn test_hmac_tampered_message_fails() {
        let message = b"Original message";
        let key = b"secret key";

        let tag = hmac(message, key, SecurityMode::Unverified).expect("HMAC should succeed");

        let tampered_message = b"Tampered message";
        let is_valid = hmac_check(tampered_message, key, &tag, SecurityMode::Unverified)
            .expect("HMAC verify should succeed");

        assert!(!is_valid, "Tampered message should fail HMAC verification");
    }

    #[test]
    fn test_hmac_deterministic_produces_same_tag_is_deterministic() {
        let message = b"Test message";
        let key = b"test key";

        let tag1 = hmac(message, key, SecurityMode::Unverified).expect("HMAC should succeed");
        let tag2 = hmac(message, key, SecurityMode::Unverified).expect("HMAC should succeed");

        assert_eq!(tag1, tag2, "Same inputs should produce same HMAC");
    }

    #[test]
    fn test_hmac_empty_message_roundtrip() {
        let message = b"";
        let key = b"key";

        let tag = hmac(message, key, SecurityMode::Unverified).expect("HMAC should succeed");
        let is_valid = hmac_check(message, key, &tag, SecurityMode::Unverified)
            .expect("HMAC verify should succeed");

        assert!(is_valid, "Empty message HMAC should verify");
    }

    // ============================================================================
    // Key Derivation Tests
    // ============================================================================

    #[test]
    fn test_key_derivation_deterministic_produces_same_key_is_deterministic() {
        let master_key = b"master secret key";
        let context = b"encryption-key";

        let derived1 = derive_key(master_key, context, 32, SecurityMode::Unverified)
            .expect("key derivation should succeed");
        let derived2 = derive_key(master_key, context, 32, SecurityMode::Unverified)
            .expect("key derivation should succeed");

        assert_eq!(derived1, derived2, "Same inputs should derive same key");
    }

    #[test]
    fn test_key_derivation_different_contexts_produce_different_keys_succeeds() {
        let master_key = b"master secret key";
        let context1 = b"encryption-key";
        let context2 = b"signing-key";

        let derived1 = derive_key(master_key, context1, 32, SecurityMode::Unverified)
            .expect("key derivation should succeed");
        let derived2 = derive_key(master_key, context2, 32, SecurityMode::Unverified)
            .expect("key derivation should succeed");

        assert_ne!(derived1, derived2, "Different contexts should derive different keys");
    }

    #[test]
    fn test_key_derivation_different_lengths_has_correct_sizes_has_correct_size() {
        let master_key = b"master secret key";
        let context = b"key-context";

        let key16 = derive_key(master_key, context, 16, SecurityMode::Unverified)
            .expect("key derivation should succeed");
        let key32 = derive_key(master_key, context, 32, SecurityMode::Unverified)
            .expect("key derivation should succeed");

        assert_eq!(key16.len(), 16);
        assert_eq!(key32.len(), 32);
        // First 16 bytes should be the same
        assert_eq!(&key16[..], &key32[..16]);
    }

    #[test]
    fn test_derived_key_can_be_used_for_encryption_roundtrip() {
        let master_key = b"master secret key for derivation";
        let context = b"aes-encryption-key";

        let derived_key = derive_key(master_key, context, 32, SecurityMode::Unverified)
            .expect("key derivation should succeed");
        let plaintext = b"Data encrypted with derived key";

        let ciphertext = encrypt_aes_gcm(plaintext, &derived_key, SecurityMode::Unverified)
            .expect("encryption with derived key should succeed");
        let decrypted = decrypt_aes_gcm(&ciphertext, &derived_key, SecurityMode::Unverified)
            .expect("decryption with derived key should succeed");

        assert_eq!(decrypted.as_slice(), plaintext);
    }

    // ============================================================================
    // Large Data Tests
    // ============================================================================

    #[test]
    fn test_large_data_encryption_roundtrip() {
        // Test with 1MB of data
        let large_data = vec![0x42u8; 1_000_000];
        let key = [0x42u8; 32];

        let ciphertext = encrypt_aes_gcm(&large_data, &key, SecurityMode::Unverified)
            .expect("large data encryption should succeed");
        let decrypted = decrypt_aes_gcm(&ciphertext, &key, SecurityMode::Unverified)
            .expect("large data decryption should succeed");

        assert_eq!(
            decrypted.as_slice(),
            large_data.as_slice(),
            "Large data roundtrip should preserve data"
        );
    }

    // ============================================================================
    // Edge Cases
    // ============================================================================

    #[test]
    fn test_single_byte_encryption_roundtrip() {
        let single_byte = b"X";
        let key = [0x42u8; 32];

        let ciphertext = encrypt_aes_gcm(single_byte, &key, SecurityMode::Unverified)
            .expect("single byte encryption should succeed");
        let decrypted = decrypt_aes_gcm(&ciphertext, &key, SecurityMode::Unverified)
            .expect("single byte decryption should succeed");

        assert_eq!(decrypted.as_slice(), single_byte);
    }

    #[test]
    fn test_unicode_data_encryption_roundtrip() {
        let unicode_data = "こんにちは世界 🌍 مرحبا بالعالم";
        let key = [0x42u8; 32];

        let ciphertext = encrypt_aes_gcm(unicode_data.as_bytes(), &key, SecurityMode::Unverified)
            .expect("unicode encryption should succeed");
        let decrypted = decrypt_aes_gcm(&ciphertext, &key, SecurityMode::Unverified)
            .expect("unicode decryption should succeed");

        let decrypted_str = std::str::from_utf8(&decrypted).expect("should be valid UTF-8");
        assert_eq!(decrypted_str, unicode_data);
    }

    #[test]
    fn test_binary_data_encryption_roundtrip() {
        // Test with binary data including null bytes
        let binary_data: Vec<u8> = (0..=255).collect();
        let key = [0x42u8; 32];

        let ciphertext = encrypt_aes_gcm(&binary_data, &key, SecurityMode::Unverified)
            .expect("binary encryption should succeed");
        let decrypted = decrypt_aes_gcm(&ciphertext, &key, SecurityMode::Unverified)
            .expect("binary decryption should succeed");

        assert_eq!(decrypted.as_slice(), binary_data.as_slice());
    }

    // ============================================================================
    // Integration: Key Derivation + Encryption + HMAC
    // ============================================================================

    #[test]
    fn test_multiple_keys_from_single_master_are_independent_succeeds() {
        let master_key = b"master key for multi-purpose derivation";

        // Derive separate keys for different purposes
        let enc_key = derive_key(master_key, b"encryption", 32, SecurityMode::Unverified)
            .expect("derivation should succeed");
        let mac_key = derive_key(master_key, b"authentication", 32, SecurityMode::Unverified)
            .expect("derivation should succeed");

        // Verify keys are different
        assert_ne!(enc_key, mac_key, "Different contexts should derive different keys");

        // Use encryption key for AES-GCM
        let plaintext = b"Confidential data";
        let ciphertext = encrypt_aes_gcm(plaintext, &enc_key, SecurityMode::Unverified)
            .expect("encryption should succeed");

        // Use MAC key for HMAC
        let tag =
            hmac(&ciphertext, &mac_key, SecurityMode::Unverified).expect("HMAC should succeed");
        let is_valid = hmac_check(&ciphertext, &mac_key, &tag, SecurityMode::Unverified)
            .expect("verify should succeed");
        assert!(is_valid, "HMAC should verify");

        // Decrypt and verify original data
        let decrypted = decrypt_aes_gcm(&ciphertext, &enc_key, SecurityMode::Unverified)
            .expect("decryption should succeed");
        assert_eq!(decrypted.as_slice(), plaintext);
    }

    #[test]
    fn test_encrypt_then_mac_pattern_succeeds() {
        let plaintext = b"Important data requiring both confidentiality and integrity";

        // Use different keys for encryption and authentication (good practice)
        let enc_key =
            derive_key(b"master", b"enc", 32, SecurityMode::Unverified).expect("key derivation");
        let mac_key =
            derive_key(b"master", b"mac", 32, SecurityMode::Unverified).expect("key derivation");

        // Encrypt
        let ciphertext =
            encrypt_aes_gcm(plaintext, &enc_key, SecurityMode::Unverified).expect("encryption");

        // Compute HMAC over ciphertext (Encrypt-then-MAC)
        let tag = hmac(&ciphertext, &mac_key, SecurityMode::Unverified).expect("HMAC");

        // Verify MAC first
        assert!(
            hmac_check(&ciphertext, &mac_key, &tag, SecurityMode::Unverified).expect("verify"),
            "MAC should verify"
        );

        // Then decrypt
        let decrypted =
            decrypt_aes_gcm(&ciphertext, &enc_key, SecurityMode::Unverified).expect("decryption");
        assert_eq!(decrypted.as_slice(), plaintext);
    }

    #[test]
    fn test_hash_then_sign_pattern_succeeds() {
        // Simulating a hash-then-sign pattern (without actual signing, just HMAC for demo)
        let document = b"Important legal document content";

        // Hash the document
        let doc_hash = hash_data(document);

        // "Sign" the hash (using HMAC as a stand-in for actual signature)
        let signing_key = b"document signing key";
        let signature = hmac(&doc_hash, signing_key, SecurityMode::Unverified).expect("HMAC");

        // Verify
        let is_valid = hmac_check(&doc_hash, signing_key, &signature, SecurityMode::Unverified)
            .expect("verify");
        assert!(is_valid, "Hash+HMAC verification should pass");
    }

    #[test]
    fn test_complete_secure_message_workflow_succeeds() {
        // Complete workflow: derive keys, encrypt, authenticate
        let master_secret = b"shared master secret between parties";

        // Derive encryption and MAC keys
        let enc_key =
            derive_key(master_secret, b"message-encryption", 32, SecurityMode::Unverified)
                .expect("enc key derivation");
        let mac_key =
            derive_key(master_secret, b"message-authentication", 32, SecurityMode::Unverified)
                .expect("mac key derivation");

        // Original message
        let message = b"Secret message: Meet at location X at time Y";

        // Encrypt the message
        let ciphertext =
            encrypt_aes_gcm(message, &enc_key, SecurityMode::Unverified).expect("encryption");

        // Create HMAC over ciphertext
        let mac = hmac(&ciphertext, &mac_key, SecurityMode::Unverified).expect("HMAC");

        // Simulate transmission: (ciphertext, mac)

        // Receiver side: verify MAC first
        let mac_valid =
            hmac_check(&ciphertext, &mac_key, &mac, SecurityMode::Unverified).expect("MAC verify");
        assert!(mac_valid, "MAC should verify");

        // Then decrypt
        let decrypted =
            decrypt_aes_gcm(&ciphertext, &enc_key, SecurityMode::Unverified).expect("decryption");
        assert_eq!(decrypted.as_slice(), message, "Original message recovered");
    }
}
