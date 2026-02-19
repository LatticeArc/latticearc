// Tests are allowed to use unwrap/expect for simplicity
// (Allow attributes are on the `mod tests;` declaration in lib.rs)

use crate::unified_api::*;

#[test]
fn test_basic_encryption() {
    std::thread::Builder::new()
        .name("test_basic_encryption".to_string())
        .stack_size(32 * 1024 * 1024)
        .spawn(|| {
            let data = b"Hello, LatticeArc Core!";
            let key = vec![1u8; 32];

            // Test symmetric encryption with AES-256-GCM
            let encrypted =
                encrypt_aes_gcm_unverified(data, &key).expect("Encryption should succeed");

            // Test decryption
            let decrypted =
                decrypt_aes_gcm_unverified(&encrypted, &key).expect("Decryption should succeed");

            // Verify round-trip
            assert_eq!(data, decrypted.as_slice(), "Decryption should match original data");
        })
        .unwrap()
        .join()
        .unwrap();
}

#[test]
fn test_basic_signing() {
    std::thread::Builder::new()
        .name("test_basic_signing".to_string())
        .stack_size(32 * 1024 * 1024)
        .spawn(|| {
            let message = b"Important message";

            // Test signing with persistent keypair API
            let config = CryptoConfig::new();
            let (pk, sk, _scheme) =
                generate_signing_keypair(config).expect("Keygen should succeed");
            let signed = sign_with_key(message, &sk, &pk, CryptoConfig::new())
                .expect("Signing should succeed");

            // Test verification
            let verified =
                verify(&signed, CryptoConfig::new()).expect("Verification should succeed");

            assert!(verified, "Signature verification should succeed");
        })
        .unwrap()
        .join()
        .unwrap();
}

#[test]
fn test_keypair_generation() {
    std::thread::Builder::new()
        .name("test_keypair_generation".to_string())
        .stack_size(32 * 1024 * 1024)
        .spawn(|| {
            let result = generate_keypair();
            assert!(result.is_ok(), "Keypair generation failed: {:?}", result.err());

            let (public_key, private_key) = result.unwrap();
            assert_eq!(public_key.len(), 32);
            assert_eq!(private_key.len(), 32);
        })
        .unwrap()
        .join()
        .unwrap();
}

#[test]
fn test_configuration_validation() {
    let config = CoreConfig::new();
    let result = config.validate();
    assert!(result.is_ok(), "Default config validation failed: {:?}", result.err());

    let invalid_config = CoreConfig::new()
        .with_security_level(SecurityLevel::Maximum)
        .with_hardware_acceleration(false);
    let result = invalid_config.validate();
    assert!(result.is_err(), "Invalid config should fail validation");
}

#[test]
fn test_zero_trust_authentication() {
    std::thread::Builder::new()
        .name("test_zero_trust_authentication".to_string())
        .stack_size(32 * 1024 * 1024)
        .spawn(|| {
            let (public_key, private_key) = generate_keypair().unwrap();
            let auth = ZeroTrustAuth::new(public_key, private_key);
            assert!(auth.is_ok(), "ZeroTrustAuth creation failed: {:?}", auth.err());

            let auth = auth.unwrap();
            let challenge = auth.generate_challenge().unwrap();
            let proof = auth.generate_proof(&challenge.data);
            assert!(proof.is_ok(), "Proof generation failed: {:?}", proof.err());

            let proof = proof.unwrap();
            let verified = auth.verify_proof(&proof, &challenge.data);
            assert!(verified.unwrap(), "Proof verification failed");
        })
        .unwrap()
        .join()
        .unwrap();
}

#[test]
fn test_verified_session_establishment() {
    std::thread::Builder::new()
        .name("test_verified_session_establishment".to_string())
        .stack_size(32 * 1024 * 1024)
        .spawn(|| {
            let (public_key, private_key) = generate_keypair().unwrap();
            let session = VerifiedSession::establish(public_key.as_slice(), private_key.as_slice());
            assert!(session.is_ok(), "Session establishment failed: {:?}", session.err());

            let session = session.unwrap();
            assert!(session.is_valid(), "Session should be valid");
            assert_eq!(session.trust_level(), TrustLevel::Trusted);
        })
        .unwrap()
        .join()
        .unwrap();
}

#[test]
fn test_session_verified_encryption() {
    std::thread::Builder::new()
        .name("test_session_verified_encryption".to_string())
        .stack_size(32 * 1024 * 1024)
        .spawn(|| {
            // Establish session
            let (public_key, private_key) = generate_keypair().unwrap();
            let session =
                VerifiedSession::establish(public_key.as_slice(), private_key.as_slice()).unwrap();

            // Verify session is valid
            assert!(session.is_valid(), "Session should be valid");
            assert_eq!(session.trust_level(), TrustLevel::Trusted);

            let data = b"Hello, Zero Trust!";
            let key = vec![1u8; 32];

            // Test symmetric encryption with AES-256-GCM
            // Note: The unified encrypt() API with CryptoConfig defaults to hybrid PQ encryption
            // which requires ML-KEM public keys. For symmetric encryption, use explicit functions.
            let encrypted =
                encrypt_aes_gcm_unverified(data, &key).expect("Encryption should succeed");

            // Test decryption
            let decrypted =
                decrypt_aes_gcm_unverified(&encrypted, &key).expect("Decryption should succeed");

            assert_eq!(data, decrypted.as_slice());
        })
        .unwrap()
        .join()
        .unwrap();
}

#[test]
fn test_use_case_config() {
    let config = UseCaseConfig::new(UseCase::SecureMessaging);
    let result = config.validate();
    assert!(result.is_ok(), "UseCaseConfig validation failed: {:?}", result.err());
}

#[test]
fn test_hardware_types_exist() {
    // Hardware trait definitions and types are available
    let info = HardwareInfo {
        available_accelerators: vec![HardwareType::Cpu],
        preferred_accelerator: Some(HardwareType::Cpu),
        capabilities: HardwareCapabilities {
            simd_support: true,
            aes_ni: true,
            threads: 1,
            memory: 0,
        },
    };

    assert!(!info.available_accelerators.is_empty());
    assert!(info.best_accelerator().is_some());
}

#[test]
fn test_context_aware_selection() {
    let config = CoreConfig::default();
    let data = b"test data for context-aware selection";

    let result = CryptoPolicyEngine::select_for_context(data, &config);
    assert!(result.is_ok(), "Context-aware selection failed: {:?}", result.err());

    let scheme = result.unwrap();
    assert!(scheme.contains("hybrid"), "Default scheme should be hybrid");
}

#[test]
fn test_encryption_decryption_with_security_level() {
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            let data = b"Test data with config";
            let key = vec![2u8; 32];

            // Test symmetric encryption with AES-256-GCM
            // Note: The unified encrypt() API with CryptoConfig defaults to hybrid PQ encryption
            // which requires ML-KEM public keys. For symmetric key encryption, use the
            // explicit AES-GCM functions.
            let encrypted = encrypt_aes_gcm_unverified(data, &key);
            assert!(encrypted.is_ok(), "Encryption failed: {:?}", encrypted.err());

            let encrypted = encrypted.unwrap();
            let decrypted = decrypt_aes_gcm_unverified(&encrypted, &key);
            assert!(decrypted.is_ok(), "Decryption failed: {:?}", decrypted.err());

            assert_eq!(data, decrypted.unwrap().as_slice());
        })
        .unwrap()
        .join()
        .unwrap();
}

#[test]
fn test_signature_verification_with_use_case() {
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            let message = b"Test signature with use case";

            // Test signing with High security level (uses ml-dsa-65-ed25519 which works correctly)
            let config = CryptoConfig::new().security_level(SecurityLevel::High);
            let (pk, sk, _scheme) =
                generate_signing_keypair(config).expect("Keygen should succeed");
            let signed = sign_with_key(
                message,
                &sk,
                &pk,
                CryptoConfig::new().security_level(SecurityLevel::High),
            );
            assert!(signed.is_ok(), "Signing failed: {:?}", signed.err());

            let signed = signed.unwrap();
            let verified = verify(&signed, CryptoConfig::new());
            assert!(verified.is_ok(), "Verification failed: {:?}", verified.err());

            assert!(verified.unwrap());
        })
        .unwrap()
        .join()
        .unwrap();
}

#[test]
fn test_key_derivation() {
    let password = b"test_password";
    let salt = b"test_salt";
    let length = 32;

    let result = derive_key_unverified(password, salt, length);
    assert!(result.is_ok(), "Key derivation failed: {:?}", result.err());

    let key = result.unwrap();
    assert_eq!(key.len(), length);
}

#[test]
fn test_hmac() {
    let key = b"test_hmac_key";
    let data = b"test data for hmac";

    let result = hmac_unverified(key, data);
    assert!(result.is_ok(), "HMAC generation failed: {:?}", result.err());

    let hmac_tag = result.unwrap();
    assert_eq!(hmac_tag.len(), 32);

    let verification = hmac_check_unverified(key, data, &hmac_tag);
    assert!(verification.is_ok(), "HMAC verification failed: {:?}", verification.err());
    assert!(verification.unwrap());
}

#[test]
fn test_initialization() {
    std::thread::Builder::new()
        .name("test_initialization".to_string())
        .stack_size(32 * 1024 * 1024)
        .spawn(|| {
            let result = init();
            assert!(result.is_ok(), "Initialization failed: {:?}", result.err());

            let config = CoreConfig::new();
            let result = init_with_config(&config);
            assert!(result.is_ok(), "Initialization with config failed: {:?}", result.err());
        })
        .unwrap()
        .join()
        .unwrap();
}

#[test]
fn test_version() {
    assert!(!VERSION.is_empty());
    assert!(VERSION.contains('.'));
}

// ============================================================================
// Unified API Tests for Encryption Schemes
// ============================================================================

#[test]
fn test_unified_api_aes_gcm_roundtrip() {
    std::thread::Builder::new()
        .name("test_unified_api_aes_gcm_roundtrip".to_string())
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            let data = b"Test data for AES-GCM encryption";
            let key = vec![0x42u8; 32];

            // AES-GCM with 32-byte key should work
            let encrypted =
                encrypt_aes_gcm_unverified(data, &key).expect("AES-GCM encryption should succeed");

            let decrypted = decrypt_aes_gcm_unverified(&encrypted, &key)
                .expect("AES-GCM decryption should succeed");

            assert_eq!(data.as_slice(), decrypted.as_slice());
        })
        .unwrap()
        .join()
        .unwrap();
}

#[test]
fn test_unified_api_hybrid_scheme_falls_back_to_aes_gcm() {
    std::thread::Builder::new()
        .name("test_unified_api_hybrid_fallback".to_string())
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            // When the selector picks a hybrid scheme but the caller provides a
            // symmetric key, the unified API falls back to AES-256-GCM.
            // True hybrid encryption requires encrypt_hybrid() with typed keys.

            let data = b"Test data for unified API hybrid fallback";
            let symmetric_key = vec![0x42u8; 32];

            use crate::UseCase;
            let config = CryptoConfig::new().use_case(UseCase::FileStorage);

            // This should succeed — falls back to AES-256-GCM with the symmetric key
            let encrypted = encrypt(data, &symmetric_key, config)
                .expect("Unified API should fall back to AES-256-GCM for symmetric keys");

            // The stored scheme should be aes-256-gcm (the actual encryption used)
            assert_eq!(
                encrypted.scheme, "aes-256-gcm",
                "Scheme should be aes-256-gcm after fallback, got: {}",
                encrypted.scheme
            );

            // Roundtrip: decrypt should work with the same key
            let decrypted = decrypt(&encrypted, &symmetric_key, CryptoConfig::new())
                .expect("Decryption should succeed with the same symmetric key");
            assert_eq!(data.as_slice(), decrypted.as_slice());
        })
        .unwrap()
        .join()
        .unwrap();
}

#[test]
fn test_unified_api_default_encrypt_decrypt_roundtrip() {
    std::thread::Builder::new()
        .name("test_unified_api_default_roundtrip".to_string())
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            // The default CryptoConfig (SecurityLevel::High) should work with
            // the unified API and a 32-byte symmetric key.
            let data = b"Default unified API roundtrip test";
            let key = vec![0x55u8; 32];

            let encrypted =
                encrypt(data, &key, CryptoConfig::new()).expect("Default encrypt should succeed");

            assert_eq!(encrypted.scheme, "aes-256-gcm");

            let decrypted = decrypt(&encrypted, &key, CryptoConfig::new())
                .expect("Default decrypt should succeed");

            assert_eq!(data.as_slice(), decrypted.as_slice());
        })
        .unwrap()
        .join()
        .unwrap();
}

#[test]
fn test_unified_api_all_use_cases_roundtrip() {
    std::thread::Builder::new()
        .name("test_unified_api_all_use_cases".to_string())
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            use crate::UseCase;

            let data = b"Roundtrip test for all use cases";
            let key = vec![0xAAu8; 32];

            let use_cases = [
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
            ];

            for uc in &use_cases {
                let config = CryptoConfig::new().use_case(uc.clone());
                let encrypted = encrypt(data, &key, config)
                    .unwrap_or_else(|e| panic!("encrypt failed for {:?}: {}", uc, e));

                // Scheme name varies by use case (some produce signature scheme names)
                // but all paths use AES-256-GCM internally with symmetric keys
                assert!(!encrypted.scheme.is_empty(), "UseCase {:?} should have a scheme", uc);

                let decrypted = decrypt(&encrypted, &key, CryptoConfig::new())
                    .unwrap_or_else(|e| panic!("decrypt failed for {:?}: {}", uc, e));
                assert_eq!(data.as_slice(), decrypted.as_slice(), "UseCase {:?}", uc);
            }
        })
        .unwrap()
        .join()
        .unwrap();
}

#[test]
fn test_unified_api_all_security_levels_roundtrip() {
    std::thread::Builder::new()
        .name("test_unified_api_all_security_levels".to_string())
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            let data = b"Roundtrip test for all security levels";
            let key = vec![0xBBu8; 32];

            let levels = [
                SecurityLevel::Standard,
                SecurityLevel::High,
                SecurityLevel::Maximum,
                SecurityLevel::Quantum,
            ];

            for level in &levels {
                let config = CryptoConfig::new().security_level(level.clone());
                let encrypted = encrypt(data, &key, config)
                    .unwrap_or_else(|e| panic!("encrypt failed for {:?}: {}", level, e));

                // Scheme name varies by level (Quantum produces pq- prefix)
                // but all paths use AES-256-GCM internally with symmetric keys
                assert!(
                    !encrypted.scheme.is_empty(),
                    "SecurityLevel {:?} should have a scheme",
                    level
                );

                let decrypted = decrypt(&encrypted, &key, CryptoConfig::new())
                    .unwrap_or_else(|e| panic!("decrypt failed for {:?}: {}", level, e));
                assert_eq!(data.as_slice(), decrypted.as_slice(), "SecurityLevel {:?}", level);
            }
        })
        .unwrap()
        .join()
        .unwrap();
}

#[test]
fn test_unified_api_rejects_short_key() {
    std::thread::Builder::new()
        .name("test_unified_api_rejects_short_key".to_string())
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            let data = b"Test data";
            let short_key = vec![0x42u8; 16]; // Too short

            let result = encrypt(data, &short_key, CryptoConfig::new());
            assert!(result.is_err(), "Should reject key shorter than 32 bytes");
        })
        .unwrap()
        .join()
        .unwrap();
}

/// Test hybrid encryption roundtrip with ML-KEM-768 + X25519.
///
/// Uses the true hybrid API that combines ML-KEM + X25519 ECDH + HKDF + AES-GCM.
#[test]
fn test_hybrid_encryption_roundtrip() {
    std::thread::Builder::new()
        .name("test_hybrid_encryption_roundtrip".to_string())
        .stack_size(32 * 1024 * 1024)
        .spawn(|| {
            use crate::unified_api::convenience::{
                decrypt_hybrid, encrypt_hybrid, generate_hybrid_keypair,
            };
            use crate::unified_api::zero_trust::SecurityMode;

            let data = b"Secret message for hybrid encryption test";

            // Generate hybrid keypair (ML-KEM-768 + X25519)
            let (pk, sk) =
                generate_hybrid_keypair().expect("Hybrid keypair generation should succeed");

            // Encrypt
            let encrypted = encrypt_hybrid(data, &pk, SecurityMode::Unverified)
                .expect("Hybrid encryption should succeed");

            // Verify structure
            assert_eq!(encrypted.kem_ciphertext.len(), 1088, "ML-KEM-768 CT should be 1088 bytes");
            assert_eq!(encrypted.ecdh_ephemeral_pk.len(), 32, "X25519 PK should be 32 bytes");
            assert_eq!(encrypted.nonce.len(), 12, "AES-GCM nonce should be 12 bytes");
            assert_eq!(encrypted.tag.len(), 16, "AES-GCM tag should be 16 bytes");

            // Decrypt
            let decrypted = decrypt_hybrid(&encrypted, &sk, SecurityMode::Unverified)
                .expect("Hybrid decryption should succeed");

            assert_eq!(data.as_slice(), decrypted.as_slice());
        })
        .unwrap()
        .join()
        .unwrap();
}

#[test]
fn test_scheme_selection_for_security_levels() {
    // Test that the CryptoPolicyEngine correctly selects schemes based on security level
    let data = b"test data";

    // Standard level should select ML-KEM-512
    let config_standard = CoreConfig::default().with_security_level(SecurityLevel::Standard);
    let scheme_standard =
        CryptoPolicyEngine::select_encryption_scheme(data, &config_standard, None)
            .expect("Scheme selection should succeed");
    assert!(
        scheme_standard.contains("512"),
        "Standard should select ML-KEM-512: {}",
        scheme_standard
    );

    // High level should select ML-KEM-768
    let config_high = CoreConfig::default().with_security_level(SecurityLevel::High);
    let scheme_high = CryptoPolicyEngine::select_encryption_scheme(data, &config_high, None)
        .expect("Scheme selection should succeed");
    assert!(scheme_high.contains("768"), "High should select ML-KEM-768: {}", scheme_high);

    // Maximum level should select ML-KEM-1024
    let config_max = CoreConfig::default().with_security_level(SecurityLevel::Maximum);
    let scheme_max = CryptoPolicyEngine::select_encryption_scheme(data, &config_max, None)
        .expect("Scheme selection should succeed");
    assert!(scheme_max.contains("1024"), "Maximum should select ML-KEM-1024: {}", scheme_max);
}

#[test]
fn test_encrypted_data_contains_scheme_metadata() {
    std::thread::Builder::new()
        .name("test_encrypted_data_contains_scheme_metadata".to_string())
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            let data = b"Test data for metadata verification";
            let key = vec![0x42u8; 32];

            // Use low-level AES-GCM to create EncryptedData
            let ciphertext =
                encrypt_aes_gcm_unverified(data, &key).expect("Encryption should succeed");

            // Create EncryptedData with scheme
            use crate::types::{EncryptedData, EncryptedMetadata};
            let encrypted = EncryptedData {
                data: ciphertext.clone(),
                metadata: EncryptedMetadata {
                    nonce: ciphertext.get(..12).map_or_else(Vec::new, <[u8]>::to_vec),
                    tag: Some(
                        ciphertext
                            .get(ciphertext.len().saturating_sub(16)..)
                            .map_or_else(Vec::new, <[u8]>::to_vec),
                    ),
                    key_id: None,
                },
                scheme: "aes-256-gcm".to_string(),
                timestamp: 0,
            };

            // Verify scheme is stored correctly
            assert_eq!(encrypted.scheme, "aes-256-gcm");

            // Verify decryption works
            let decrypted =
                decrypt(&encrypted, &key, CryptoConfig::new()).expect("Decryption should succeed");
            assert_eq!(data.as_slice(), decrypted.as_slice());
        })
        .unwrap()
        .join()
        .unwrap();
}

#[test]
fn test_decrypt_honors_scheme_from_encrypted_data() {
    std::thread::Builder::new()
        .name("test_decrypt_honors_scheme".to_string())
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            let data = b"Test that decrypt honors the scheme field";
            let key = vec![0x42u8; 32];

            // Encrypt with AES-GCM
            let ciphertext =
                encrypt_aes_gcm_unverified(data, &key).expect("Encryption should succeed");

            // Create EncryptedData with correct AES-GCM scheme
            use crate::types::{EncryptedData, EncryptedMetadata};
            let encrypted = EncryptedData {
                data: ciphertext,
                metadata: EncryptedMetadata { nonce: vec![], tag: None, key_id: None },
                scheme: "aes-256-gcm".to_string(),
                timestamp: 0,
            };

            // Decrypt should use scheme from EncryptedData, not from CryptoConfig
            let decrypted = decrypt(&encrypted, &key, CryptoConfig::new())
                .expect("Decryption should succeed using scheme from EncryptedData");
            assert_eq!(data.as_slice(), decrypted.as_slice());
        })
        .unwrap()
        .join()
        .unwrap();
}

// ============================================================================
// Phase 4: lib.rs coverage (init, self_tests_passed, VERSION)
// ============================================================================

#[test]
fn test_init() {
    std::thread::Builder::new()
        .name("test_init".to_string())
        .stack_size(32 * 1024 * 1024)
        .spawn(|| {
            let result = crate::init();
            assert!(result.is_ok(), "init() should succeed");
        })
        .unwrap()
        .join()
        .unwrap();
}

#[test]
fn test_init_with_config_default() {
    std::thread::Builder::new()
        .name("test_init_with_config_default".to_string())
        .stack_size(32 * 1024 * 1024)
        .spawn(|| {
            let config = crate::unified_api::CoreConfig::default();
            let result = crate::init_with_config(&config);
            assert!(result.is_ok(), "init_with_config with defaults should succeed");
        })
        .unwrap()
        .join()
        .unwrap();
}

#[test]
fn test_self_tests_passed_after_init() {
    std::thread::Builder::new()
        .name("test_self_tests_passed".to_string())
        .stack_size(32 * 1024 * 1024)
        .spawn(|| {
            // Run init to ensure self-tests pass
            let _ = crate::init();
            assert!(
                crate::unified_api::self_tests_passed(),
                "self_tests_passed should be true after init"
            );
        })
        .unwrap()
        .join()
        .unwrap();
}

#[test]
fn test_version_constant() {
    assert!(!crate::VERSION.is_empty(), "VERSION should not be empty");
    // Should be a semver-like string
    assert!(crate::VERSION.contains('.'), "VERSION should contain a dot separator");
}

#[test]
fn test_init_with_invalid_config() {
    // Invalid config should fail validation before self-tests
    let invalid_config = crate::unified_api::CoreConfig::new()
        .with_security_level(SecurityLevel::Maximum)
        .with_hardware_acceleration(false);
    let result = crate::init_with_config(&invalid_config);
    assert!(result.is_err(), "init_with_config should fail with invalid config");
}

#[test]
fn test_self_tests_passed_is_bool() {
    // Just verify it returns a bool without panicking
    let _passed: bool = crate::unified_api::self_tests_passed();
}

// ============================================================================
// Phase 4: types.rs coverage (ZeroizedBytes, KeyPair, enums, CryptoConfig)
// ============================================================================

#[test]
fn test_zeroized_bytes_basic() {
    let data = vec![1u8, 2, 3, 4, 5];
    let zb = ZeroizedBytes::new(data.clone());
    assert_eq!(zb.as_slice(), &[1, 2, 3, 4, 5]);
    assert_eq!(zb.len(), 5);
    assert!(!zb.is_empty());
    // AsRef trait
    let slice: &[u8] = zb.as_ref();
    assert_eq!(slice, &[1, 2, 3, 4, 5]);
    // Debug trait
    let debug = format!("{:?}", zb);
    assert!(debug.contains("ZeroizedBytes"));
}

#[test]
fn test_zeroized_bytes_empty() {
    let zb = ZeroizedBytes::new(vec![]);
    assert!(zb.is_empty());
    assert_eq!(zb.len(), 0);
    assert_eq!(zb.as_slice(), &[] as &[u8]);
}

#[test]
fn test_keypair_accessors() {
    let pk = vec![10u8, 20, 30];
    let sk = ZeroizedBytes::new(vec![40, 50, 60]);
    let kp = KeyPair::new(pk.clone(), sk);
    assert_eq!(kp.public_key(), &pk);
    assert_eq!(kp.private_key().as_slice(), &[40, 50, 60]);
    // Direct field access
    assert_eq!(kp.public_key, pk);
    assert_eq!(kp.private_key.as_slice(), &[40, 50, 60]);
}

#[test]
fn test_security_level_variants() {
    let standard = SecurityLevel::Standard;
    let high = SecurityLevel::High;
    let maximum = SecurityLevel::Maximum;
    let quantum = SecurityLevel::Quantum;

    // Default is High
    assert_eq!(SecurityLevel::default(), SecurityLevel::High);

    // Clone and PartialEq
    assert_eq!(standard.clone(), SecurityLevel::Standard);
    assert_eq!(high.clone(), SecurityLevel::High);
    assert_eq!(maximum.clone(), SecurityLevel::Maximum);
    assert_eq!(quantum.clone(), SecurityLevel::Quantum);

    // All variants are distinct
    assert_ne!(standard, high);
    assert_ne!(high, maximum);
    assert_ne!(maximum, quantum);
}

#[test]
fn test_performance_preference_variants() {
    let speed = PerformancePreference::Speed;
    let memory = PerformancePreference::Memory;
    let balanced = PerformancePreference::Balanced;

    // Default is Balanced
    assert_eq!(PerformancePreference::default(), PerformancePreference::Balanced);

    // All distinct
    assert_ne!(speed, memory);
    assert_ne!(memory, balanced);
    assert_ne!(speed, balanced);

    // Clone
    assert_eq!(speed.clone(), PerformancePreference::Speed);
}

#[test]
fn test_use_case_all_variants() {
    // Ensure all 24 variants can be constructed and are distinct
    let variants: Vec<UseCase> = vec![
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
    assert_eq!(variants.len(), 24);

    // Each variant should be unique
    for (i, a) in variants.iter().enumerate() {
        for (j, b) in variants.iter().enumerate() {
            if i != j {
                assert_ne!(a, b, "UseCase variants at {} and {} should differ", i, j);
            }
        }
    }
}

#[test]
fn test_crypto_scheme_variants() {
    let hybrid = CryptoScheme::Hybrid;
    let symmetric = CryptoScheme::Symmetric;
    let asymmetric = CryptoScheme::Asymmetric;
    let homomorphic = CryptoScheme::Homomorphic;
    let pq = CryptoScheme::PostQuantum;

    assert_ne!(hybrid, symmetric);
    assert_ne!(symmetric, asymmetric);
    assert_ne!(asymmetric, homomorphic);
    assert_ne!(homomorphic, pq);

    // Clone
    assert_eq!(hybrid.clone(), CryptoScheme::Hybrid);
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
fn test_algorithm_selection_default() {
    let sel = AlgorithmSelection::default();
    assert_eq!(sel, AlgorithmSelection::SecurityLevel(SecurityLevel::High));
}

#[test]
fn test_algorithm_selection_variants() {
    let by_use_case = AlgorithmSelection::UseCase(UseCase::FileStorage);
    let by_level = AlgorithmSelection::SecurityLevel(SecurityLevel::Maximum);
    assert_ne!(by_use_case, by_level);

    // Clone
    assert_eq!(by_use_case.clone(), AlgorithmSelection::UseCase(UseCase::FileStorage));
}

#[test]
fn test_crypto_config_builder() {
    let config = CryptoConfig::new();
    assert!(config.get_session().is_none());
    assert!(!config.is_verified());
    assert_eq!(*config.get_selection(), AlgorithmSelection::default());
    // validate with no session should succeed
    assert!(config.validate().is_ok());
}

#[test]
fn test_crypto_config_use_case() {
    let config = CryptoConfig::new().use_case(UseCase::HealthcareRecords);
    assert_eq!(*config.get_selection(), AlgorithmSelection::UseCase(UseCase::HealthcareRecords));
}

#[test]
fn test_crypto_config_security_level() {
    let config = CryptoConfig::new().security_level(SecurityLevel::Maximum);
    assert_eq!(*config.get_selection(), AlgorithmSelection::SecurityLevel(SecurityLevel::Maximum));
}

#[test]
fn test_crypto_config_default_trait() {
    let config: CryptoConfig<'_> = CryptoConfig::default();
    assert!(config.get_session().is_none());
    assert_eq!(*config.get_selection(), AlgorithmSelection::default());
}

#[test]
fn test_encrypted_metadata() {
    let meta = EncryptedMetadata {
        nonce: vec![1, 2, 3],
        tag: Some(vec![4, 5, 6]),
        key_id: Some("key-1".to_string()),
    };
    let meta2 = meta.clone();
    assert_eq!(meta, meta2);
    assert_eq!(meta.nonce, vec![1, 2, 3]);
    assert_eq!(meta.tag, Some(vec![4, 5, 6]));
    assert_eq!(meta.key_id, Some("key-1".to_string()));

    // Without optional fields
    let meta3 = EncryptedMetadata { nonce: vec![], tag: None, key_id: None };
    assert_ne!(meta, meta3);
}

#[test]
fn test_signed_metadata() {
    let meta = SignedMetadata {
        signature: vec![1, 2, 3],
        signature_algorithm: "ed25519".to_string(),
        public_key: vec![4, 5, 6],
        key_id: Some("sig-key-1".to_string()),
    };
    let meta2 = meta.clone();
    assert_eq!(meta.signature, meta2.signature);
    assert_eq!(meta.signature_algorithm, meta2.signature_algorithm);
    assert_eq!(meta.public_key, meta2.public_key);
    assert_eq!(meta.key_id, meta2.key_id);
}

#[test]
fn test_encrypted_data_type_alias() {
    let encrypted = EncryptedData {
        data: vec![10, 20, 30],
        metadata: EncryptedMetadata { nonce: vec![1], tag: None, key_id: None },
        scheme: "aes-256-gcm".to_string(),
        timestamp: 1234567890,
    };
    let encrypted2 = encrypted.clone();
    assert_eq!(encrypted, encrypted2);
    assert_eq!(encrypted.scheme, "aes-256-gcm");
    assert_eq!(encrypted.timestamp, 1234567890);
}

#[test]
fn test_crypto_config_overrides() {
    // Setting use_case then security_level should use security_level
    let config =
        CryptoConfig::new().use_case(UseCase::FileStorage).security_level(SecurityLevel::Standard);
    assert_eq!(*config.get_selection(), AlgorithmSelection::SecurityLevel(SecurityLevel::Standard));

    // Setting security_level then use_case should use use_case
    let config2 =
        CryptoConfig::new().security_level(SecurityLevel::Standard).use_case(UseCase::VpnTunnel);
    assert_eq!(*config2.get_selection(), AlgorithmSelection::UseCase(UseCase::VpnTunnel));
}

// ============================================================================
// Phase 4: traits.rs coverage (VerificationStatus, HardwareInfo)
// ============================================================================

#[test]
fn test_verification_status_is_verified() {
    assert!(VerificationStatus::Verified.is_verified());
    assert!(!VerificationStatus::Expired.is_verified());
    assert!(!VerificationStatus::Failed.is_verified());
    assert!(!VerificationStatus::Pending.is_verified());
}

#[test]
fn test_hardware_info_best_accelerator_preferred() {
    let info = HardwareInfo {
        available_accelerators: vec![HardwareType::Cpu, HardwareType::Gpu],
        preferred_accelerator: Some(HardwareType::Gpu),
        capabilities: HardwareCapabilities {
            simd_support: true,
            aes_ni: true,
            threads: 4,
            memory: 1024,
        },
    };
    assert_eq!(info.best_accelerator(), Some(&HardwareType::Gpu));
}

#[test]
fn test_hardware_info_best_accelerator_fallback_to_first() {
    let info = HardwareInfo {
        available_accelerators: vec![HardwareType::Fpga, HardwareType::Cpu],
        preferred_accelerator: None,
        capabilities: HardwareCapabilities {
            simd_support: false,
            aes_ni: false,
            threads: 1,
            memory: 512,
        },
    };
    assert_eq!(info.best_accelerator(), Some(&HardwareType::Fpga));
}

#[test]
fn test_hardware_info_best_accelerator_none() {
    let info = HardwareInfo {
        available_accelerators: vec![],
        preferred_accelerator: None,
        capabilities: HardwareCapabilities {
            simd_support: false,
            aes_ni: false,
            threads: 1,
            memory: 256,
        },
    };
    assert_eq!(info.best_accelerator(), None);
}

#[test]
fn test_hardware_info_summary() {
    let info = HardwareInfo {
        available_accelerators: vec![HardwareType::Cpu],
        preferred_accelerator: Some(HardwareType::Cpu),
        capabilities: HardwareCapabilities {
            simd_support: true,
            aes_ni: true,
            threads: 8,
            memory: 4096,
        },
    };
    let summary = info.summary();
    assert!(summary.contains("Cpu"), "Summary should mention Cpu");
    assert!(summary.contains("Available"), "Summary should mention Available");
    assert!(summary.contains("Preferred"), "Summary should mention Preferred");
}

#[test]
fn test_hardware_type_variants() {
    let types = vec![
        HardwareType::Cpu,
        HardwareType::Gpu,
        HardwareType::Fpga,
        HardwareType::Tpu,
        HardwareType::Sgx,
    ];
    // All should be clonable and debug-formattable
    for t in &types {
        let cloned = t.clone();
        assert_eq!(t, &cloned);
        let debug = format!("{:?}", t);
        assert!(!debug.is_empty());
    }
}

#[test]
fn test_data_characteristics_fields() {
    let dc = DataCharacteristics { size: 1024, entropy: 7.5, pattern_type: PatternType::Random };
    assert_eq!(dc.size, 1024);
    assert!((dc.entropy - 7.5).abs() < f64::EPSILON);
    assert_eq!(dc.pattern_type, PatternType::Random);

    let dc2 = dc.clone();
    assert_eq!(dc2.size, dc.size);
}

#[test]
fn test_pattern_type_variants() {
    let patterns = vec![
        PatternType::Random,
        PatternType::Structured,
        PatternType::Repetitive,
        PatternType::Text,
        PatternType::Binary,
    ];
    for (i, a) in patterns.iter().enumerate() {
        for (j, b) in patterns.iter().enumerate() {
            if i == j {
                assert_eq!(a, b);
            } else {
                assert_ne!(a, b);
            }
        }
    }
}

// ============================================================================
// Phase 4: AES-GCM with verified session
// ============================================================================

#[test]
fn test_aes_gcm_with_verified_session() {
    std::thread::Builder::new()
        .name("test_aes_gcm_verified".to_string())
        .stack_size(32 * 1024 * 1024)
        .spawn(|| {
            use crate::unified_api::zero_trust::SecurityMode;

            let (pk, sk) = generate_keypair().unwrap();
            let session = VerifiedSession::establish(&pk, sk.as_slice()).unwrap();

            let key = vec![0x42u8; 32];
            let data = b"Verified AES-GCM test";

            let encrypted = encrypt_aes_gcm(data, &key, SecurityMode::Verified(&session)).unwrap();
            let decrypted =
                decrypt_aes_gcm(&encrypted, &key, SecurityMode::Verified(&session)).unwrap();
            assert_eq!(data.as_slice(), decrypted.as_slice());
        })
        .unwrap()
        .join()
        .unwrap();
}

#[test]
fn test_aes_gcm_with_config_verified_session() {
    std::thread::Builder::new()
        .name("test_aes_gcm_config_verified".to_string())
        .stack_size(32 * 1024 * 1024)
        .spawn(|| {
            use crate::unified_api::zero_trust::SecurityMode;

            let (pk, sk) = generate_keypair().unwrap();
            let session = VerifiedSession::establish(&pk, sk.as_slice()).unwrap();
            let config = crate::unified_api::config::CoreConfig::default();

            let key = vec![0x42u8; 32];
            let data = b"Config verified AES-GCM test";

            let encrypted =
                encrypt_aes_gcm_with_config(data, &key, &config, SecurityMode::Verified(&session))
                    .unwrap();
            let decrypted = decrypt_aes_gcm_with_config(
                &encrypted,
                &key,
                &config,
                SecurityMode::Verified(&session),
            )
            .unwrap();
            assert_eq!(data.as_slice(), decrypted.as_slice());
        })
        .unwrap()
        .join()
        .unwrap();
}

// ============================================================================
// Phase 4: api.rs - generate_signing_keypair with specific schemes
// ============================================================================

#[test]
fn test_generate_signing_keypair_quantum_level() {
    std::thread::Builder::new()
        .name("keygen_quantum".to_string())
        .stack_size(32 * 1024 * 1024)
        .spawn(|| {
            let config = CryptoConfig::new().security_level(SecurityLevel::Quantum);
            let result = generate_signing_keypair(config);
            assert!(result.is_ok(), "Quantum level keypair generation should succeed");
            let (pk, sk, scheme) = result.unwrap();
            assert!(!pk.is_empty());
            assert!(!sk.is_empty());
            assert!(!scheme.is_empty());
        })
        .unwrap()
        .join()
        .unwrap();
}

#[test]
fn test_generate_signing_keypair_all_use_cases() {
    std::thread::Builder::new()
        .name("keygen_use_cases".to_string())
        .stack_size(32 * 1024 * 1024)
        .spawn(|| {
            // Only signing-oriented use cases can generate signing keypairs.
            // Encryption-oriented use cases (IoT, FileStorage, etc.) correctly
            // return errors because their schemes are for encryption, not signing.
            let signing_use_cases = vec![
                UseCase::Authentication,
                UseCase::DigitalCertificate,
                UseCase::FinancialTransactions,
                UseCase::LegalDocuments,
                UseCase::BlockchainTransaction,
                UseCase::FirmwareSigning,
            ];
            for uc in signing_use_cases {
                let config = CryptoConfig::new().use_case(uc.clone());
                let result = generate_signing_keypair(config);
                assert!(result.is_ok(), "Keypair generation failed for {:?}", uc);
            }

            // Encryption-oriented use cases should fail keygen
            let encryption_use_cases = vec![
                UseCase::SecureMessaging,
                UseCase::IoTDevice,
                UseCase::GovernmentClassified,
                UseCase::HealthcareRecords,
                UseCase::PaymentCard,
                UseCase::AuditLog,
            ];
            for uc in encryption_use_cases {
                let config = CryptoConfig::new().use_case(uc.clone());
                let result = generate_signing_keypair(config);
                assert!(
                    result.is_err(),
                    "Encryption use case {:?} should not produce signing keypair",
                    uc
                );
            }
        })
        .unwrap()
        .join()
        .unwrap();
}

// ============================================================================
// Phase 4: api.rs - sign_with_key error paths for hybrid schemes
// ============================================================================

#[test]
fn test_sign_with_key_hybrid_44_wrong_sk_length() {
    std::thread::Builder::new()
        .name("hybrid44_bad_sk".to_string())
        .stack_size(32 * 1024 * 1024)
        .spawn(|| {
            let message = b"test";
            let wrong_sk = vec![0u8; 100]; // Wrong length for hybrid-44
            let wrong_pk = vec![0u8; 100];
            let config = CryptoConfig::new().security_level(SecurityLevel::Standard);

            // First check what scheme Standard gives us
            let (pk, sk, scheme) = generate_signing_keypair(config.clone()).unwrap();
            if scheme.contains("hybrid-ml-dsa-44") {
                // Now try with wrong key lengths
                let result = sign_with_key(message, &wrong_sk, &pk, config.clone());
                assert!(result.is_err(), "Should fail with wrong SK length");

                let result2 = sign_with_key(message, &sk, &wrong_pk, config);
                assert!(result2.is_err(), "Should fail with wrong PK length");
            }
        })
        .unwrap()
        .join()
        .unwrap();
}

#[test]
fn test_sign_with_key_hybrid_87_wrong_key_lengths() {
    std::thread::Builder::new()
        .name("hybrid87_bad_keys".to_string())
        .stack_size(32 * 1024 * 1024)
        .spawn(|| {
            let message = b"test";
            let config = CryptoConfig::new().security_level(SecurityLevel::Maximum);

            let (pk, sk, scheme) = generate_signing_keypair(config.clone()).unwrap();
            if scheme.contains("hybrid-ml-dsa-87") {
                // Wrong SK length
                let wrong_sk = vec![0u8; 100];
                let result = sign_with_key(message, &wrong_sk, &pk, config.clone());
                assert!(result.is_err(), "Should fail with wrong SK length for hybrid-87");

                // Wrong PK length
                let wrong_pk = vec![0u8; 100];
                let result2 = sign_with_key(message, &sk, &wrong_pk, config);
                assert!(result2.is_err(), "Should fail with wrong PK length for hybrid-87");
            }
        })
        .unwrap()
        .join()
        .unwrap();
}

// ============================================================================
// Phase 4: verify() error paths for hybrid signature validation
// ============================================================================

#[test]
fn test_verify_hybrid_44_short_signature() {
    let signed = SignedData {
        data: b"test".to_vec(),
        metadata: SignedMetadata {
            signature: vec![0u8; 10], // Too short for hybrid-44
            signature_algorithm: "hybrid-ml-dsa-44-ed25519".to_string(),
            public_key: vec![0u8; 1344], // 1312 + 32
            key_id: None,
        },
        scheme: "hybrid-ml-dsa-44-ed25519".to_string(),
        timestamp: 0,
    };

    let result = verify(&signed, CryptoConfig::new());
    assert!(result.is_err(), "Should fail with too-short hybrid-44 signature");
}

#[test]
fn test_verify_hybrid_44_wrong_pk_length() {
    let signed = SignedData {
        data: b"test".to_vec(),
        metadata: SignedMetadata {
            signature: vec![0u8; 2500], // Long enough
            signature_algorithm: "hybrid-ml-dsa-44-ed25519".to_string(),
            public_key: vec![0u8; 100], // Wrong length (should be 1312 + 32 = 1344)
            key_id: None,
        },
        scheme: "hybrid-ml-dsa-44-ed25519".to_string(),
        timestamp: 0,
    };

    let result = verify(&signed, CryptoConfig::new());
    assert!(result.is_err(), "Should fail with wrong PK length for hybrid-44");
}

#[test]
fn test_verify_hybrid_87_short_signature() {
    let signed = SignedData {
        data: b"test".to_vec(),
        metadata: SignedMetadata {
            signature: vec![0u8; 10], // Too short for hybrid-87
            signature_algorithm: "hybrid-ml-dsa-87-ed25519".to_string(),
            public_key: vec![0u8; 2624], // 2592 + 32
            key_id: None,
        },
        scheme: "hybrid-ml-dsa-87-ed25519".to_string(),
        timestamp: 0,
    };

    let result = verify(&signed, CryptoConfig::new());
    assert!(result.is_err(), "Should fail with too-short hybrid-87 signature");
}

#[test]
fn test_verify_hybrid_87_wrong_pk_length() {
    let signed = SignedData {
        data: b"test".to_vec(),
        metadata: SignedMetadata {
            signature: vec![0u8; 5000], // Long enough
            signature_algorithm: "hybrid-ml-dsa-87-ed25519".to_string(),
            public_key: vec![0u8; 100], // Wrong length (should be 2592 + 32 = 2624)
            key_id: None,
        },
        scheme: "hybrid-ml-dsa-87-ed25519".to_string(),
        timestamp: 0,
    };

    let result = verify(&signed, CryptoConfig::new());
    assert!(result.is_err(), "Should fail with wrong PK length for hybrid-87");
}

#[test]
fn test_decrypt_with_short_key_unknown_scheme() {
    let encrypted = EncryptedData {
        data: vec![1, 2, 3, 4],
        metadata: EncryptedMetadata { nonce: vec![], tag: None, key_id: None },
        scheme: "unknown-scheme".to_string(),
        timestamp: 0,
    };
    let short_key = vec![0x42u8; 16];

    let result = decrypt(&encrypted, &short_key, CryptoConfig::new());
    assert!(result.is_err(), "Decrypt with short key on unknown scheme should fail");
}

#[test]
fn test_encrypt_empty_data() {
    std::thread::Builder::new()
        .name("encrypt_empty".to_string())
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            let key = vec![0x42u8; 32];
            let encrypted = encrypt(b"", &key, CryptoConfig::new()).unwrap();
            // Empty plaintext still produces ciphertext (nonce + auth tag)
            assert!(!encrypted.data.is_empty());

            let decrypted = decrypt(&encrypted, &key, CryptoConfig::new()).unwrap();
            assert!(decrypted.is_empty());
        })
        .unwrap()
        .join()
        .unwrap();
}

#[test]
fn test_verify_hybrid_65_short_signature() {
    let signed = SignedData {
        data: b"test".to_vec(),
        metadata: SignedMetadata {
            signature: vec![0u8; 10], // Too short for hybrid-65
            signature_algorithm: "hybrid-ml-dsa-65-ed25519".to_string(),
            public_key: vec![0u8; 1984], // 1952 + 32
            key_id: None,
        },
        scheme: "hybrid-ml-dsa-65-ed25519".to_string(),
        timestamp: 0,
    };

    let result = verify(&signed, CryptoConfig::new());
    assert!(result.is_err(), "Should fail with too-short hybrid-65 signature");
}

#[test]
fn test_verify_hybrid_65_wrong_pk_length() {
    let signed = SignedData {
        data: b"test".to_vec(),
        metadata: SignedMetadata {
            signature: vec![0u8; 4000], // Long enough
            signature_algorithm: "hybrid-ml-dsa-65-ed25519".to_string(),
            public_key: vec![0u8; 100], // Wrong length (should be 1952 + 32 = 1984)
            key_id: None,
        },
        scheme: "hybrid-ml-dsa-65-ed25519".to_string(),
        timestamp: 0,
    };

    let result = verify(&signed, CryptoConfig::new());
    assert!(result.is_err(), "Should fail with wrong PK length for hybrid-65");
}

// ============================================================================
// Unified API with VerifiedSession
// ============================================================================

#[test]
fn test_unified_encrypt_decrypt_with_verified_session() {
    std::thread::Builder::new()
        .name("unified_verified".to_string())
        .stack_size(32 * 1024 * 1024)
        .spawn(|| {
            let data = b"Verified session encryption test";
            let key = vec![0x42u8; 32];

            let (auth_pk, auth_sk) = generate_keypair().unwrap();
            let session = VerifiedSession::establish(&auth_pk, auth_sk.as_ref()).unwrap();

            let config = CryptoConfig::new().session(&session);
            let encrypted = encrypt(data, &key, config.clone()).unwrap();
            let decrypted = decrypt(&encrypted, &key, config).unwrap();
            assert_eq!(data.as_slice(), decrypted.as_slice());
        })
        .unwrap()
        .join()
        .unwrap();
}

#[test]
fn test_unified_sign_verify_with_verified_session() {
    std::thread::Builder::new()
        .name("sign_verified".to_string())
        .stack_size(32 * 1024 * 1024)
        .spawn(|| {
            let message = b"Verified session signing test";

            let (auth_pk, auth_sk) = generate_keypair().unwrap();
            let session = VerifiedSession::establish(&auth_pk, auth_sk.as_ref()).unwrap();

            let config = CryptoConfig::new().session(&session);
            let (pk, sk, _scheme) = generate_signing_keypair(config.clone()).unwrap();
            let signed = sign_with_key(message, &sk, &pk, config.clone()).unwrap();
            let valid = verify(&signed, config).unwrap();
            assert!(valid, "Signature should verify with verified session");
        })
        .unwrap()
        .join()
        .unwrap();
}

#[test]
fn test_encrypt_decrypt_with_use_case_secure_messaging() {
    std::thread::Builder::new()
        .name("secure_msg".to_string())
        .stack_size(32 * 1024 * 1024)
        .spawn(|| {
            let data = b"Secure messaging test";
            let key = vec![0x42u8; 32];
            let config = CryptoConfig::new().use_case(UseCase::SecureMessaging);

            let encrypted = encrypt(data, &key, config.clone()).unwrap();
            let decrypted = decrypt(&encrypted, &key, config).unwrap();
            assert_eq!(data.as_slice(), decrypted.as_slice());
        })
        .unwrap()
        .join()
        .unwrap();
}

#[test]
fn test_encrypt_decrypt_with_use_case_financial() {
    std::thread::Builder::new()
        .name("financial".to_string())
        .stack_size(32 * 1024 * 1024)
        .spawn(|| {
            let data = b"Financial transactions test";
            let key = vec![0x42u8; 32];
            let config = CryptoConfig::new().use_case(UseCase::FinancialTransactions);

            let encrypted = encrypt(data, &key, config.clone()).unwrap();
            let decrypted = decrypt(&encrypted, &key, config).unwrap();
            assert_eq!(data.as_slice(), decrypted.as_slice());
        })
        .unwrap()
        .join()
        .unwrap();
}
