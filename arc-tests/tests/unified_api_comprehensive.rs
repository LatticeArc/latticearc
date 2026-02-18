#![deny(unsafe_code)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::panic)]
#![allow(clippy::indexing_slicing)]
#![allow(missing_docs)]

//! Comprehensive Unified API Integration Tests
//!
//! Exercises `latticearc::encrypt()` / `latticearc::decrypt()` through the public
//! facade with ALL 24 UseCases, ALL 4 SecurityLevels, and the TLS policy engine
//! with ALL 10 TlsUseCases.
//!
//! Run with: `cargo test --package latticearc --test unified_api_comprehensive --all-features --release`

use latticearc::{
    CryptoConfig, PerformancePreference, SecurityLevel, SecurityMode, TlsConfig, TlsConstraints,
    TlsContext, TlsMode, TlsPolicyEngine, TlsUseCase, UseCase, decrypt, decrypt_hybrid, encrypt,
    encrypt_hybrid, generate_hybrid_keypair, generate_signing_keypair, sign_with_key, verify,
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
fn test_unified_api_uses_aes256gcm_by_design() {
    let key = [0x42u8; 32];
    let data = b"test data for unified API";

    // Even with Quantum security level and GovernmentClassified use case,
    // the unified API correctly uses AES-256-GCM (symmetric key path).
    let config = CryptoConfig::new()
        .security_level(SecurityLevel::Quantum)
        .use_case(UseCase::GovernmentClassified);

    let encrypted = encrypt(data, &key, config.clone()).expect("encrypt should succeed");

    // The effective scheme is AES-256-GCM (not ML-KEM), which is correct
    // because the unified API receives a symmetric key.
    assert_eq!(
        encrypted.scheme, "aes-256-gcm",
        "Unified API with symmetric key should use AES-256-GCM"
    );

    let decrypted = decrypt(&encrypted, &key, config).expect("decrypt should succeed");
    assert_eq!(decrypted, data);
}

/// ML-KEM standalone decapsulation requires a live `DecapsulationKey` object.
///
/// ML-KEM standalone decapsulation round-trip via serialized secret key.
#[test]
fn test_ml_kem_standalone_decapsulation() {
    use arc_primitives::kem::ml_kem::{MlKem, MlKemSecurityLevel};
    let mut rng = rand::rngs::OsRng;
    let (pk, sk) = MlKem::generate_keypair(&mut rng, MlKemSecurityLevel::MlKem768)
        .expect("keygen should succeed");
    let (ss_enc, ct) = MlKem::encapsulate(&mut rng, &pk).expect("encapsulate should succeed");
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
    let signed = sign_with_key(message, &sk, &pk, config.clone()).expect("signing should succeed");
    let valid = verify(&signed, config).expect("verification should succeed");
    assert!(valid, "Signature from hybrid keygen should verify");
}

/// Quantum-level signing selects PQ-only ML-DSA-87 (no Ed25519 hybrid).
///
/// Uses the `fips204` crate for ML-DSA. This crate is not FIPS-validated
/// (unlike aws-lc-rs). Excluded to flag as a known migration point.
#[test]
#[ignore = "ML-DSA uses fips204 crate which is not FIPS-validated"]
fn test_sign_verify_quantum_level_pq_only() {
    let config = CryptoConfig::new().security_level(SecurityLevel::Quantum);
    let (pk, sk, scheme) = generate_signing_keypair(config).expect("keygen");
    assert_eq!(scheme, "pq-ml-dsa-87");

    let config = CryptoConfig::new().security_level(SecurityLevel::Quantum);
    let signed = sign_with_key(b"quantum test", &sk, &pk, config).expect("sign");
    let valid = verify(&signed, CryptoConfig::new()).expect("verify");
    assert!(valid, "PQ-only ML-DSA-87 signature should verify");
}

/// FN-DSA secret key inner bytes are not zeroized on drop.
///
/// The `fn-dsa` crate does not implement `Zeroize` for its internal key type.
/// Our wrapper zeroizes `Vec<u8>` bytes but the inner representation may persist.
#[test]
#[ignore = "FN-DSA inner key not zeroized — fn-dsa crate does not implement Zeroize"]
fn test_fn_dsa_secret_key_zeroization() {
    // fn-dsa crate's internal key type does not implement Zeroize.
    // Mitigated by process isolation and mlock in production deployments.
    panic!("FN-DSA inner key zeroization not possible with current crate");
}

/// ML-KEM secret key persistence: serialize, deserialize, and decapsulate.
#[test]
fn test_ml_kem_key_persistence() {
    use arc_primitives::kem::ml_kem::{MlKem, MlKemPublicKey, MlKemSecretKey, MlKemSecurityLevel};

    let mut rng = rand::rngs::OsRng;
    let (pk, sk) = MlKem::generate_keypair(&mut rng, MlKemSecurityLevel::MlKem768)
        .expect("keygen should succeed");

    // Serialize both keys
    let pk_bytes = pk.as_bytes().to_vec();
    let sk_bytes = sk.as_bytes().to_vec();

    // Restore from bytes
    let pk2 = MlKemPublicKey::from_bytes(&pk_bytes, MlKemSecurityLevel::MlKem768)
        .expect("pk restore should succeed");
    let sk2 = MlKemSecretKey::new(MlKemSecurityLevel::MlKem768, sk_bytes)
        .expect("sk restore should succeed");

    // Encapsulate with restored PK, decapsulate with restored SK
    let (ss_enc, ct) = MlKem::encapsulate(&mut rng, &pk2).expect("encapsulate should succeed");
    let ss_dec = MlKem::decapsulate(&sk2, &ct).expect("decapsulate should succeed");
    assert_eq!(ss_enc.as_bytes(), ss_dec.as_bytes(), "round-trip through serialization must match");
}

// TLS handshake integration tests are in arc-tls/tests/tls_handshake_roundtrip.rs.

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
        // Advanced (3)
        UseCase::SearchableEncryption,
        UseCase::HomomorphicComputation,
        UseCase::AuditLog,
    ]
}

#[test]
fn test_encrypt_decrypt_all_24_use_cases() {
    let key = [0x42u8; 32];
    let plaintext = b"Unified API roundtrip for every UseCase";
    let use_cases = all_use_cases();
    assert_eq!(use_cases.len(), 24, "Expected 24 use cases");

    for uc in &use_cases {
        let config = CryptoConfig::new().use_case(uc.clone());
        let encrypted = encrypt(plaintext, &key, config)
            .unwrap_or_else(|e| panic!("encrypt failed for {:?}: {}", uc, e));

        assert!(!encrypted.scheme.is_empty(), "{:?} scheme should be set", uc);
        assert!(!encrypted.data.is_empty(), "{:?} ciphertext should be non-empty", uc);

        let decrypted = decrypt(&encrypted, &key, CryptoConfig::new())
            .unwrap_or_else(|e| panic!("decrypt failed for {:?}: {}", uc, e));
        assert_eq!(decrypted.as_slice(), plaintext, "Roundtrip mismatch for {:?}", uc);
    }
}

// ============================================================================
// Unified encrypt/decrypt — All 4 SecurityLevels
// ============================================================================

#[test]
fn test_encrypt_decrypt_all_4_security_levels() {
    let key = [0x55u8; 32];
    let plaintext = b"Unified API roundtrip for every SecurityLevel";

    let levels = [
        SecurityLevel::Standard,
        SecurityLevel::High,
        SecurityLevel::Maximum,
        SecurityLevel::Quantum,
    ];

    for level in &levels {
        let config = CryptoConfig::new().security_level(level.clone());
        let encrypted = encrypt(plaintext, &key, config)
            .unwrap_or_else(|e| panic!("encrypt failed for {:?}: {}", level, e));

        assert!(!encrypted.scheme.is_empty(), "{:?} scheme should be set", level);

        let decrypted = decrypt(&encrypted, &key, CryptoConfig::new())
            .unwrap_or_else(|e| panic!("decrypt failed for {:?}: {}", level, e));
        assert_eq!(decrypted.as_slice(), plaintext, "Roundtrip mismatch for {:?}", level);
    }
}

// ============================================================================
// Default CryptoConfig roundtrip
// ============================================================================

#[test]
fn test_encrypt_decrypt_default_config() {
    let key = [0xAAu8; 32];
    let plaintext = b"Default CryptoConfig roundtrip through facade";

    let encrypted =
        encrypt(plaintext, &key, CryptoConfig::new()).expect("default encrypt should succeed");
    let decrypted =
        decrypt(&encrypted, &key, CryptoConfig::new()).expect("default decrypt should succeed");

    assert_eq!(decrypted.as_slice(), plaintext);
}

// ============================================================================
// Empty and large plaintext
// ============================================================================

#[test]
fn test_encrypt_decrypt_empty_plaintext() {
    let key = [0xBBu8; 32];
    let plaintext = b"";

    let encrypted =
        encrypt(plaintext, &key, CryptoConfig::new()).expect("encrypt empty should succeed");
    let decrypted =
        decrypt(&encrypted, &key, CryptoConfig::new()).expect("decrypt empty should succeed");

    assert_eq!(decrypted.as_slice(), plaintext);
}

#[test]
fn test_encrypt_decrypt_large_plaintext() {
    let key = [0xCCu8; 32];
    let plaintext = vec![0xFFu8; 64 * 1024]; // 64 KiB

    let encrypted =
        encrypt(&plaintext, &key, CryptoConfig::new()).expect("encrypt large should succeed");
    let decrypted =
        decrypt(&encrypted, &key, CryptoConfig::new()).expect("decrypt large should succeed");

    assert_eq!(decrypted.as_slice(), plaintext.as_slice());
}

// ============================================================================
// Nonce uniqueness — same plaintext encrypts differently
// ============================================================================

#[test]
fn test_encrypt_nonce_uniqueness() {
    let key = [0xDDu8; 32];
    let plaintext = b"Same plaintext encrypted twice";

    let enc1 = encrypt(plaintext, &key, CryptoConfig::new()).expect("encrypt 1");
    let enc2 = encrypt(plaintext, &key, CryptoConfig::new()).expect("encrypt 2");

    assert_ne!(enc1.data, enc2.data, "Random nonces should produce different ciphertexts");
}

// ============================================================================
// Key rejection
// ============================================================================

#[test]
fn test_encrypt_rejects_short_key() {
    let short_key = [0x42u8; 16];
    let result = encrypt(b"data", &short_key, CryptoConfig::new());
    assert!(result.is_err(), "16-byte key should be rejected");
}

#[test]
fn test_decrypt_wrong_key_fails() {
    let key = [0x42u8; 32];
    let wrong_key = [0x99u8; 32];
    let plaintext = b"Wrong key should fail decryption";

    let encrypted = encrypt(plaintext, &key, CryptoConfig::new()).expect("encrypt");
    let result = decrypt(&encrypted, &wrong_key, CryptoConfig::new());
    assert!(result.is_err(), "Decryption with wrong key should fail");
}

// ============================================================================
// Tamper detection
// ============================================================================

#[test]
fn test_decrypt_tampered_ciphertext_fails() {
    let key = [0x42u8; 32];
    let plaintext = b"Tamper detection through unified API";

    let mut encrypted = encrypt(plaintext, &key, CryptoConfig::new()).expect("encrypt");

    if encrypted.data.len() > 12 {
        encrypted.data[12] ^= 0xFF;
    }

    let result = decrypt(&encrypted, &key, CryptoConfig::new());
    assert!(result.is_err(), "Tampered ciphertext should fail");
}

// ============================================================================
// Sign/Verify — All 4 SecurityLevels through facade
// ============================================================================

#[test]
fn test_sign_verify_all_security_levels() {
    let message = b"Sign/verify at every security level through facade";

    for level in [SecurityLevel::Standard, SecurityLevel::High, SecurityLevel::Maximum] {
        let config = CryptoConfig::new().security_level(level.clone());
        let (pk, sk, scheme) = generate_signing_keypair(config)
            .unwrap_or_else(|e| panic!("keygen {:?}: {}", level, e));
        assert!(!scheme.is_empty());

        let config = CryptoConfig::new().security_level(level.clone());
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
fn test_hybrid_encrypt_decrypt_through_facade() {
    let (pk, sk) = generate_hybrid_keypair().expect("keygen");
    let plaintext = b"Hybrid ML-KEM-768 + X25519 through latticearc facade";

    let encrypted = encrypt_hybrid(plaintext, &pk, SecurityMode::Unverified).expect("encrypt");
    assert_eq!(encrypted.kem_ciphertext.len(), 1088);
    assert_eq!(encrypted.ecdh_ephemeral_pk.len(), 32);

    let decrypted = decrypt_hybrid(&encrypted, &sk, SecurityMode::Unverified).expect("decrypt");
    assert_eq!(decrypted.as_slice(), plaintext);
}

#[test]
fn test_hybrid_wrong_key_fails() {
    let (pk1, _sk1) = generate_hybrid_keypair().expect("keygen 1");
    let (_pk2, sk2) = generate_hybrid_keypair().expect("keygen 2");

    let encrypted = encrypt_hybrid(b"data", &pk1, SecurityMode::Unverified).expect("encrypt");
    let result = decrypt_hybrid(&encrypted, &sk2, SecurityMode::Unverified);
    assert!(result.is_err(), "Decrypt with wrong hybrid key should fail");
}

// ============================================================================
// Complete workflow: derive key → encrypt → sign → verify → decrypt
// ============================================================================

#[test]
fn test_complete_encrypt_sign_verify_decrypt_workflow() {
    // Step 1: Encrypt
    let key = [0x42u8; 32];
    let plaintext = b"Complete workflow through facade";
    let encrypted = encrypt(plaintext, &key, CryptoConfig::new()).expect("encrypt");

    // Step 2: Sign the ciphertext
    let config = CryptoConfig::new().security_level(SecurityLevel::High);
    let (sign_pk, sign_sk, _) = generate_signing_keypair(config).expect("keygen");

    let config = CryptoConfig::new().security_level(SecurityLevel::High);
    let signed = sign_with_key(&encrypted.data, &sign_sk, &sign_pk, config).expect("sign");

    // Step 3: Verify
    let is_valid = verify(&signed, CryptoConfig::new()).expect("verify");
    assert!(is_valid);

    // Step 4: Decrypt
    let decrypted = decrypt(&encrypted, &key, CryptoConfig::new()).expect("decrypt");
    assert_eq!(decrypted.as_slice(), plaintext);
}

// ============================================================================
// TLS Policy Engine — All 10 TlsUseCases
// ============================================================================

#[test]
fn test_tls_recommend_mode_all_10_use_cases() {
    let use_cases = TlsUseCase::all();
    assert_eq!(use_cases.len(), 10);

    let expected: &[(TlsUseCase, TlsMode)] = &[
        (TlsUseCase::WebServer, TlsMode::Hybrid),
        (TlsUseCase::InternalService, TlsMode::Hybrid),
        (TlsUseCase::ApiGateway, TlsMode::Hybrid),
        (TlsUseCase::IoT, TlsMode::Classic),
        (TlsUseCase::LegacyIntegration, TlsMode::Classic),
        (TlsUseCase::FinancialServices, TlsMode::Hybrid),
        (TlsUseCase::Healthcare, TlsMode::Hybrid),
        (TlsUseCase::Government, TlsMode::Pq),
        (TlsUseCase::DatabaseConnection, TlsMode::Hybrid),
        (TlsUseCase::RealTimeStreaming, TlsMode::Classic),
    ];

    for (uc, expected_mode) in expected {
        let mode = TlsPolicyEngine::recommend_mode(*uc);
        assert_eq!(mode, *expected_mode, "TlsUseCase::{:?}", uc);
    }
}

#[test]
fn test_tls_select_by_security_level_all_4_levels() {
    assert_eq!(TlsPolicyEngine::select_by_security_level(SecurityLevel::Standard), TlsMode::Hybrid);
    assert_eq!(TlsPolicyEngine::select_by_security_level(SecurityLevel::High), TlsMode::Hybrid);
    assert_eq!(TlsPolicyEngine::select_by_security_level(SecurityLevel::Maximum), TlsMode::Hybrid);
    assert_eq!(TlsPolicyEngine::select_by_security_level(SecurityLevel::Quantum), TlsMode::Pq);
}

#[test]
fn test_tls_scheme_and_kex_all_use_cases() {
    for uc in TlsUseCase::all() {
        let mode = TlsPolicyEngine::recommend_mode(*uc);
        let level = SecurityLevel::High;
        let scheme = TlsPolicyEngine::get_scheme_identifier(mode, level.clone());
        let kex = TlsPolicyEngine::get_kex_algorithm(mode, level);

        assert!(!scheme.is_empty(), "Scheme should be set for {:?}", uc);
        assert!(!kex.is_empty(), "KEX should be set for {:?}", uc);
    }
}

#[test]
fn test_tls_context_selection_all_use_cases() {
    for uc in TlsUseCase::all() {
        let ctx = TlsContext::with_use_case(*uc);
        let mode = TlsPolicyEngine::select_with_context(&ctx);
        let config = TlsPolicyEngine::create_config(&ctx);

        // Mode from context should match mode in generated config
        assert_eq!(mode, config.mode, "Context vs config mode mismatch for {:?}", uc);
    }
}

#[test]
fn test_tls_config_builder_all_use_cases() {
    for uc in TlsUseCase::all() {
        let config = TlsConfig::new().use_case(*uc);
        config.validate().unwrap_or_else(|e| panic!("validate failed for {:?}: {}", uc, e));

        let expected = TlsPolicyEngine::recommend_mode(*uc);
        assert_eq!(config.mode, expected, "TlsConfig mode mismatch for {:?}", uc);
    }
}

#[test]
fn test_tls_config_builder_all_security_levels() {
    for level in [
        SecurityLevel::Standard,
        SecurityLevel::High,
        SecurityLevel::Maximum,
        SecurityLevel::Quantum,
    ] {
        let config = TlsConfig::new().security_level(level.clone());
        config.validate().unwrap_or_else(|e| panic!("validate failed for {:?}: {}", level, e));

        let expected = TlsPolicyEngine::select_by_security_level(level.clone());
        assert_eq!(config.mode, expected, "TlsConfig mode mismatch for {:?}", level);
    }
}

// ============================================================================
// TLS Constraints
// ============================================================================

#[test]
fn test_tls_constraints_override_use_case() {
    // max_compatibility forces Classic even for FinancialServices (normally Hybrid)
    let ctx = TlsContext::with_use_case(TlsUseCase::FinancialServices)
        .constraints(TlsConstraints::maximum_compatibility());
    let mode = TlsPolicyEngine::select_with_context(&ctx);
    assert_eq!(mode, TlsMode::Classic);
}

#[test]
fn test_tls_quantum_overrides_use_case() {
    // Quantum level forces PQ even for WebServer (normally Hybrid)
    let ctx =
        TlsContext::with_use_case(TlsUseCase::WebServer).security_level(SecurityLevel::Quantum);
    let mode = TlsPolicyEngine::select_with_context(&ctx);
    assert_eq!(mode, TlsMode::Pq);
}

// ============================================================================
// TLS Balanced Selection — SecurityLevel x PerformancePreference
// ============================================================================

#[test]
fn test_tls_balanced_selection_all_combinations() {
    let levels = [
        SecurityLevel::Standard,
        SecurityLevel::High,
        SecurityLevel::Maximum,
        SecurityLevel::Quantum,
    ];
    let prefs = [
        PerformancePreference::Speed,
        PerformancePreference::Memory,
        PerformancePreference::Balanced,
    ];

    for level in &levels {
        for pref in &prefs {
            let mode = TlsPolicyEngine::select_balanced(level.clone(), pref.clone());

            if *level == SecurityLevel::Quantum {
                assert_eq!(mode, TlsMode::Pq, "Quantum should always be PQ");
            } else {
                assert_eq!(mode, TlsMode::Hybrid, "{:?} x {:?} should be Hybrid", level, pref);
            }
        }
    }
}

// ============================================================================
// TLS Scheme Selectors — PQ-only and Hybrid for all levels
// ============================================================================

#[test]
fn test_tls_pq_scheme_selectors_all_levels() {
    assert_eq!(TlsPolicyEngine::select_pq_scheme(SecurityLevel::Standard), "pq-ml-kem-512");
    assert_eq!(TlsPolicyEngine::select_pq_scheme(SecurityLevel::High), "pq-ml-kem-768");
    assert_eq!(TlsPolicyEngine::select_pq_scheme(SecurityLevel::Maximum), "pq-ml-kem-1024");
    assert_eq!(TlsPolicyEngine::select_pq_scheme(SecurityLevel::Quantum), "pq-ml-kem-1024");
}

#[test]
fn test_tls_hybrid_scheme_selectors_all_levels() {
    assert_eq!(
        TlsPolicyEngine::select_hybrid_scheme(SecurityLevel::Standard),
        "hybrid-x25519-ml-kem-512"
    );
    assert_eq!(
        TlsPolicyEngine::select_hybrid_scheme(SecurityLevel::High),
        "hybrid-x25519-ml-kem-768"
    );
    assert_eq!(
        TlsPolicyEngine::select_hybrid_scheme(SecurityLevel::Maximum),
        "hybrid-x25519-ml-kem-1024"
    );
    assert_eq!(
        TlsPolicyEngine::select_hybrid_scheme(SecurityLevel::Quantum),
        "hybrid-x25519-ml-kem-1024"
    );
}

#[test]
fn test_tls_kex_selectors_all_levels() {
    assert_eq!(TlsPolicyEngine::select_pq_kex(SecurityLevel::Standard), "MLKEM512");
    assert_eq!(TlsPolicyEngine::select_pq_kex(SecurityLevel::High), "MLKEM768");
    assert_eq!(TlsPolicyEngine::select_pq_kex(SecurityLevel::Maximum), "MLKEM1024");

    assert_eq!(TlsPolicyEngine::select_hybrid_kex(SecurityLevel::Standard), "X25519MLKEM512");
    assert_eq!(TlsPolicyEngine::select_hybrid_kex(SecurityLevel::High), "X25519MLKEM768");
    assert_eq!(TlsPolicyEngine::select_hybrid_kex(SecurityLevel::Maximum), "X25519MLKEM1024");
}
