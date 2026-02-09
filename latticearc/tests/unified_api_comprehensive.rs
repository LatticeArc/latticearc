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
// Each #[ignore] test documents a real limitation. The test body describes what
// would be tested and why it's blocked. Run with `--include-ignored` to see
// the full list. These must be revisited as upstream issues are resolved.
// ============================================================================

/// The unified `encrypt()`/`decrypt()` API uses AES-256-GCM with symmetric keys.
/// The `&[u8]` key interface cannot carry ML-KEM/X25519 typed keys, so KEM is
/// not possible through this API. This is by design (issue #18, closed).
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

/// C2: ML-KEM standalone decapsulation always fails.
///
/// `MlKem::decapsulate()` returns an error because aws-lc-rs `DecapsulationKey`
/// cannot be reconstructed from raw bytes. Only `MlKemDecapsulationKeyPair`
/// (which holds the live aws-lc-rs object) can decapsulate.
///
/// Tracking: GitHub issue #16, upstream aws-lc-rs#1029
#[test]
#[ignore = "ML-KEM standalone decapsulate() always fails — blocked on aws-lc-rs#1029 (issue #16)"]
fn test_ml_kem_standalone_decapsulation() {
    // What this WOULD test: Generate ML-KEM keypair, serialize secret key bytes,
    // reconstruct DecapsulationKey from bytes, decapsulate successfully.
    //
    // Reality: aws-lc-rs DecapsulationKey has no from_bytes() constructor.
    // Our MlKem::decapsulate() returns "does not support DecapsulationKey
    // deserialization" error.
    //
    // Workaround: Use encrypt_hybrid()/decrypt_hybrid() which keeps
    // DecapsulationKey alive in memory (never serializes it).
    //
    // Tracking: aws-lc-rs PR #1029 (under review by justsmth)
    panic!("ML-KEM DecapsulationKey cannot be deserialized from bytes");
}

/// Hybrid signing keygen uses the correct Ed25519 `generate_keypair()` from
/// `arc-core::convenience::keygen`, NOT the buggy X25519 one from
/// `arc-primitives::kem::ecdh` (which is properly `#[deprecated]`).
/// Issue #19 was closed as false alarm — the two functions were confused.
#[test]
fn test_hybrid_signing_keygen_is_correct() {
    let config = CryptoConfig::new().security_level(SecurityLevel::High);
    let (pk, sk, scheme) =
        generate_signing_keypair(config.clone()).expect("hybrid signing keygen should succeed");

    assert!(
        scheme.contains("hybrid") || scheme.contains("ed25519"),
        "Scheme should be hybrid or ed25519, got: {scheme}"
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
/// This test is excluded from the main sign/verify test because it uses the
/// fips204 crate which may behave differently from the future aws-lc-rs ML-DSA.
///
/// Tracking: GitHub issue #17, awaiting aws-lc-rs ML-DSA stabilization
#[test]
#[ignore = "Quantum signing uses fips204 ML-DSA-87 — awaiting aws-lc-rs stabilization (issue #17)"]
fn test_sign_verify_quantum_level_pq_only() {
    // What this tests: SecurityLevel::Quantum selects pq-ml-dsa-87 (PQ-only,
    // no Ed25519). This actually works today via fips204 crate, but the
    // implementation will migrate to aws-lc-rs once ML-DSA is stabilized.
    //
    // We exclude it from the main test to flag it as a known migration point.
    // The fips204 crate is NOT FIPS-validated (unlike aws-lc-rs).
    //
    // Tracking: aws-lc-rs issue #964 (stabilization), #773 (ML-DSA support)
    // Our PR: aws-lc-rs#1034 (seed-based keygen)
    let config = CryptoConfig::new().security_level(SecurityLevel::Quantum);
    let (pk, sk, scheme) = generate_signing_keypair(config).expect("keygen");
    assert_eq!(scheme, "pq-ml-dsa-87");

    let config = CryptoConfig::new().security_level(SecurityLevel::Quantum);
    let signed = sign_with_key(b"quantum test", &sk, &pk, config).expect("sign");
    let valid = verify(&signed, CryptoConfig::new()).expect("verify");
    assert!(valid, "PQ-only ML-DSA-87 signature should verify");
    // NOTE: This test actually passes — it's ignored to flag the fips204→aws-lc-rs
    // migration dependency, not because it fails.
}

/// #10: FN-DSA secret key inner bytes are not zeroized on drop.
///
/// The fn-dsa crate does not implement Zeroize for its internal key type.
/// We wrap it but cannot zeroize the inner representation.
#[test]
#[ignore = "FN-DSA inner key not zeroized on drop — upstream fn-dsa crate limitation (issue #10)"]
fn test_fn_dsa_secret_key_zeroization() {
    // What this WOULD test: After dropping an FN-DSA secret key, verify that
    // the memory region is zeroed (no residual key material).
    //
    // Reality: fn-dsa crate's internal key type does not implement Zeroize.
    // We zeroize our wrapper's Vec<u8> but the fn-dsa internal representation
    // may retain key material in memory.
    //
    // Impact: Secret key material may persist in memory after logical deletion.
    // Mitigated by process isolation and mlock in production deployments.
    //
    // Tracking: GitHub issue #10 (upstream limitation, no fix available)
    panic!("FN-DSA inner key zeroization blocked on upstream crate");
}

/// ML-KEM DecapsulationKey cannot be serialized for persistent storage.
///
/// In-memory usage works (encrypt_hybrid/decrypt_hybrid), but there is no way
/// to save a DecapsulationKey to disk and reload it later.
///
/// Tracking: GitHub issue #16, upstream aws-lc-rs#1029
#[test]
#[ignore = "ML-KEM DecapsulationKey not serializable — blocked on aws-lc-rs#1029 (issue #16)"]
fn test_ml_kem_key_persistence() {
    // What this WOULD test: Generate ML-KEM keypair, serialize DecapsulationKey
    // to bytes, store to file/DB, reload, decapsulate successfully.
    //
    // Reality: aws-lc-rs DecapsulationKey has no to_bytes()/from_bytes() API.
    // Keys are ephemeral — they exist only in memory for the session.
    //
    // Impact: Cannot implement persistent key storage, key rotation with
    // stored keys, or key backup/recovery for ML-KEM.
    //
    // Workaround: Use X25519 (which supports seed persistence via
    // Curve25519SeedBin) alongside ML-KEM in hybrid mode.
    //
    // Tracking: aws-lc-rs PR #1029 adds serialization (under review)
    panic!("ML-KEM key persistence blocked on aws-lc-rs#1029");
}

// NOTE: TLS handshake integration tests (classic, hybrid, PQ, ALPN, mTLS,
// multi-message, large data) are in arc-tls/tests/tls_handshake_roundtrip.rs.
// Previously an ignored test here documented the gap — now removed since
// tls_handshake_roundtrip.rs covers real TLS 1.3 handshakes with self-signed
// certs, loopback TCP connections, and PQ key exchange verification.

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
