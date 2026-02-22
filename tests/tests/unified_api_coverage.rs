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
fn test_encrypt_default_config() {
    let key = vec![0x42u8; 32];
    let data = b"Test data for default config";
    let config = CryptoConfig::new();

    let encrypted = encrypt(
        data.as_ref(),
        EncryptKey::Symmetric(key.as_ref()),
        config.force_scheme(CryptoScheme::Symmetric),
    )
    .unwrap();
    assert!(!encrypted.ciphertext.is_empty());
    assert!(!encrypted.scheme.as_str().is_empty());
}

#[test]
fn test_encrypt_use_case_file_storage() {
    let key = vec![0x42u8; 32];
    let data = b"File storage encryption test";
    let config = CryptoConfig::new().use_case(UseCase::FileStorage);

    let encrypted = encrypt(
        data.as_ref(),
        EncryptKey::Symmetric(key.as_ref()),
        config.force_scheme(CryptoScheme::Symmetric),
    )
    .unwrap();
    assert!(!encrypted.ciphertext.is_empty());
}

#[test]
fn test_encrypt_use_case_secure_messaging() {
    let key = vec![0x42u8; 32];
    let data = b"Secure messaging encryption test";
    let config = CryptoConfig::new().use_case(UseCase::SecureMessaging);

    let encrypted = encrypt(
        data.as_ref(),
        EncryptKey::Symmetric(key.as_ref()),
        config.force_scheme(CryptoScheme::Symmetric),
    )
    .unwrap();
    assert!(!encrypted.ciphertext.is_empty());
}

#[test]
fn test_encrypt_use_case_iot_device() {
    let key = vec![0x42u8; 32];
    let data = b"IoT device encryption test";
    let config = CryptoConfig::new().use_case(UseCase::IoTDevice);

    let encrypted = encrypt(
        data.as_ref(),
        EncryptKey::Symmetric(key.as_ref()),
        config.force_scheme(CryptoScheme::Symmetric),
    )
    .unwrap();
    assert!(!encrypted.ciphertext.is_empty());
}

#[test]
fn test_encrypt_security_level_maximum() {
    let key = vec![0x42u8; 32];
    let data = b"Maximum security level encryption";
    let config = CryptoConfig::new().security_level(SecurityLevel::Maximum);

    let encrypted = encrypt(
        data.as_ref(),
        EncryptKey::Symmetric(key.as_ref()),
        config.force_scheme(CryptoScheme::Symmetric),
    )
    .unwrap();
    assert!(!encrypted.ciphertext.is_empty());
}

#[test]
fn test_encrypt_security_level_standard() {
    let key = vec![0x42u8; 32];
    let data = b"Standard security level encryption";
    let config = CryptoConfig::new().security_level(SecurityLevel::Standard);

    let encrypted = encrypt(
        data.as_ref(),
        EncryptKey::Symmetric(key.as_ref()),
        config.force_scheme(CryptoScheme::Symmetric),
    )
    .unwrap();
    assert!(!encrypted.ciphertext.is_empty());
}

#[test]
fn test_encrypt_security_level_high() {
    let key = vec![0x42u8; 32];
    let data = b"High security level encryption";
    let config = CryptoConfig::new().security_level(SecurityLevel::High);

    let encrypted = encrypt(
        data.as_ref(),
        EncryptKey::Symmetric(key.as_ref()),
        config.force_scheme(CryptoScheme::Symmetric),
    )
    .unwrap();
    assert!(!encrypted.ciphertext.is_empty());
}

#[test]
fn test_encrypt_invalid_key_too_short() {
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
fn test_encrypt_empty_data() {
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
    assert!(!encrypted.ciphertext.is_empty());
}

// ============================================================
// decrypt() with different scheme names
// ============================================================

#[test]
fn test_encrypt_decrypt_roundtrip_default() {
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
    assert_eq!(decrypted, data);
}

#[test]
fn test_encrypt_decrypt_roundtrip_file_storage() {
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
    assert_eq!(decrypted, data);
}

#[test]
fn test_encrypt_decrypt_roundtrip_iot() {
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
    assert_eq!(decrypted, data);
}

#[test]
fn test_decrypt_empty_data() {
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
fn test_decrypt_invalid_key_too_short() {
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
fn test_sign_verify_authentication_use_case_keypair() {
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
fn test_sign_verify_iot_use_case_rejected() {
    // IoT use case maps to an encryption scheme, not a signing scheme
    let config = CryptoConfig::new().use_case(UseCase::IoTDevice);
    let result = generate_signing_keypair(config);
    assert!(result.is_err(), "IoT encryption scheme should not be used for signing");
}

#[test]
fn test_sign_verify_default_scheme() {
    let config = CryptoConfig::new();
    let (pk, sk, scheme) = generate_signing_keypair(config.clone()).unwrap();

    let message = b"Default scheme sign/verify test";
    let signed = sign_with_key(message, &sk, &pk, config.clone()).unwrap();
    let valid = verify(&signed, config).unwrap();
    assert!(valid, "Default scheme {} should verify", scheme);
}

#[test]
fn test_sign_verify_maximum_security() {
    let config = CryptoConfig::new().security_level(SecurityLevel::Maximum);
    let (pk, sk, scheme) = generate_signing_keypair(config.clone()).unwrap();

    let message = b"Maximum security sign test";
    let signed = sign_with_key(message, &sk, &pk, config.clone()).unwrap();
    let valid = verify(&signed, config).unwrap();
    assert!(valid, "Max security scheme {} should verify", scheme);
}

#[test]
fn test_sign_verify_standard_security() {
    let config = CryptoConfig::new().security_level(SecurityLevel::Standard);
    let (pk, sk, scheme) = generate_signing_keypair(config.clone()).unwrap();

    let message = b"Standard security sign test";
    let signed = sign_with_key(message, &sk, &pk, config.clone()).unwrap();
    let valid = verify(&signed, config).unwrap();
    assert!(valid, "Standard security scheme {} should verify", scheme);
}

#[test]
fn test_sign_verify_file_storage_use_case_rejected() {
    // FileStorage maps to an encryption scheme (hybrid-ml-kem-1024-aes-256-gcm),
    // not a signing scheme. Keygen should reject it.
    let config = CryptoConfig::new().use_case(UseCase::FileStorage);
    let result = generate_signing_keypair(config);
    assert!(result.is_err(), "FileStorage encryption scheme should not be used for signing");
}

#[test]
fn test_sign_verify_secure_messaging_use_case_rejected() {
    // SecureMessaging maps to an encryption scheme (hybrid-ml-kem-768-aes-256-gcm),
    // not a signing scheme. Keygen should reject it.
    let config = CryptoConfig::new().use_case(UseCase::SecureMessaging);
    let result = generate_signing_keypair(config);
    assert!(result.is_err(), "SecureMessaging encryption scheme should not be used for signing");
}

// ============================================================
// PQ-only (Quantum) security level
// ============================================================

#[test]
fn test_sign_verify_quantum_security() {
    let config = CryptoConfig::new().security_level(SecurityLevel::Quantum);
    let (pk, sk, scheme) = generate_signing_keypair(config.clone()).unwrap();
    assert!(
        scheme.contains("ml-dsa") || scheme.contains("pq-ml-dsa"),
        "Quantum should use pure ML-DSA, got: {}",
        scheme
    );

    let message = b"Quantum security sign test";
    let signed = sign_with_key(message, &sk, &pk, config.clone()).unwrap();
    let valid = verify(&signed, config).unwrap();
    assert!(valid, "Quantum scheme {} should verify", scheme);
}

#[test]
fn test_encrypt_security_level_quantum() {
    let key = vec![0x42u8; 32];
    let data = b"Quantum security level encryption";
    let config = CryptoConfig::new().security_level(SecurityLevel::Quantum);

    let encrypted = encrypt(
        data.as_ref(),
        EncryptKey::Symmetric(key.as_ref()),
        config.clone().force_scheme(CryptoScheme::Symmetric),
    )
    .unwrap();
    assert!(!encrypted.ciphertext.is_empty());
    let decrypted = decrypt(&encrypted, DecryptKey::Symmetric(&key), config).unwrap();
    assert_eq!(decrypted, data);
}

// ============================================================
// UseCase-based signing (hits Ed25519 fallback for KEM use cases)
// ============================================================

#[test]
fn test_sign_verify_authentication_use_case() {
    let config = CryptoConfig::new().use_case(UseCase::Authentication);
    let (pk, sk, scheme) = generate_signing_keypair(config.clone()).unwrap();

    let message = b"Authentication signing test";
    let signed = sign_with_key(message, &sk, &pk, config.clone()).unwrap();
    let valid = verify(&signed, config).unwrap();
    assert!(valid, "Authentication scheme {} should verify", scheme);
}

#[test]
fn test_sign_verify_financial_use_case() {
    let config = CryptoConfig::new().use_case(UseCase::FinancialTransactions);
    // Override auto-FIPS only when feature not available (test verifies signing, not FIPS)
    let config = if fips_available() { config } else { config.compliance(ComplianceMode::Default) };
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
fn test_unified_api_init() {
    let result = latticearc::unified_api::init();
    assert!(result.is_ok(), "init() should succeed");
}

#[test]
fn test_unified_api_init_with_default_config() {
    let config = latticearc::unified_api::config::CoreConfig::default();
    let result = latticearc::unified_api::init_with_config(&config);
    assert!(result.is_ok(), "init_with_config(default) should succeed");
}

#[test]
fn test_self_tests_passed() {
    // Run init first to ensure self-tests have run
    let _ = latticearc::unified_api::init();
    assert!(
        latticearc::unified_api::self_tests_passed(),
        "Self-tests should have passed after init"
    );
}

#[test]
fn test_version_string() {
    assert!(!latticearc::unified_api::VERSION.is_empty(), "VERSION should not be empty");
}

// ============================================================
// Error paths in verify
// ============================================================

#[test]
fn test_verify_with_wrong_signature() {
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
fn test_verify_with_wrong_message() {
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
fn test_sign_hybrid_44_sk_wrong_length() {
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
fn test_sign_hybrid_pk_wrong_length() {
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
fn test_sign_hybrid_65_sk_wrong_length() {
    let config = CryptoConfig::new().security_level(SecurityLevel::High);
    let (pk, sk, scheme) = generate_signing_keypair(config.clone()).unwrap();

    if scheme.contains("hybrid") {
        let short_sk = &sk[..sk.len() / 2];
        let result = sign_with_key(b"test", short_sk, &pk, config);
        assert!(result.is_err(), "Truncated hybrid-65 sk should fail: scheme={}", scheme);
    }
}

#[test]
fn test_sign_hybrid_87_sk_wrong_length() {
    let config = CryptoConfig::new().security_level(SecurityLevel::Maximum);
    let (pk, sk, scheme) = generate_signing_keypair(config.clone()).unwrap();

    if scheme.contains("hybrid") {
        let short_sk = &sk[..sk.len() / 2];
        let result = sign_with_key(b"test", short_sk, &pk, config);
        assert!(result.is_err(), "Truncated hybrid-87 sk should fail: scheme={}", scheme);
    }
}

#[test]
fn test_sign_hybrid_87_pk_wrong_length() {
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
fn test_verify_pq_ml_dsa_44_scheme() {
    // Generate Quantum-level keys (pure ML-DSA, not hybrid)
    let config = CryptoConfig::new().security_level(SecurityLevel::Quantum);
    let (pk, sk, _scheme) = generate_signing_keypair(config.clone()).unwrap();

    let message = b"PQ-only ML-DSA-44 verification test";
    let mut signed = sign_with_key(message, &sk, &pk, config.clone()).unwrap();

    // Manually change scheme to pq-ml-dsa variant to hit that branch in verify
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
fn test_verify_pq_ml_dsa_65_scheme() {
    let config = CryptoConfig::new().security_level(SecurityLevel::Quantum);
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
fn test_verify_pq_ml_dsa_87_scheme() {
    let config = CryptoConfig::new().security_level(SecurityLevel::Quantum);
    let (pk, sk, _scheme) = generate_signing_keypair(config.clone()).unwrap();

    let message = b"PQ-only ML-DSA-87 verification test";
    let mut signed = sign_with_key(message, &sk, &pk, config.clone()).unwrap();

    if signed.scheme.contains("ml-dsa-87") || signed.scheme.contains("pq-ml-dsa-87") {
        signed.scheme = "pq-ml-dsa-87".to_string();
        let result = verify(&signed, config);
        match result {
            Ok(valid) => assert!(valid, "pq-ml-dsa-87 should verify with correct keys"),
            Err(e) => panic!("Unexpected error verifying pq-ml-dsa-87: {}", e),
        }
    }
}

// ============================================================
// Sign with pq-ml-dsa-* scheme name via Quantum SecurityLevel
// ============================================================

#[test]
fn test_sign_with_key_pq_ml_dsa_scheme() {
    // Quantum SecurityLevel should select pq-ml-dsa-* schemes
    let config = CryptoConfig::new().security_level(SecurityLevel::Quantum);
    let (pk, sk, scheme) = generate_signing_keypair(config.clone()).unwrap();

    assert!(
        scheme.starts_with("pq-ml-dsa") || scheme.starts_with("ml-dsa"),
        "Quantum level should use pure ML-DSA, got: {}",
        scheme
    );

    let message = b"Quantum security level signing";
    let signed = sign_with_key(message, &sk, &pk, config.clone()).unwrap();
    let valid = verify(&signed, config).unwrap();
    assert!(valid, "PQ-only scheme {} should verify correctly", scheme);
}
