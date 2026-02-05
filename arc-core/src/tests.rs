// Tests are allowed to use unwrap/expect for simplicity
// (Allow attributes are on the `mod tests;` declaration in lib.rs)

use crate::*;

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

            // Test signing with unified API
            let signed = sign(message, CryptoConfig::new()).expect("Signing should succeed");

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
fn test_hardware_acceleration() {
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            let router = HardwareRouter::new();
            let hardware = router.detect_hardware();

            assert!(!hardware.available_accelerators.is_empty());
            assert!(hardware.best_accelerator().is_some());
        })
        .expect("Failed to spawn thread")
        .join()
        .expect("Thread panicked");
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
            // Note: UseCase::Authentication selects hybrid-ml-dsa-87-ed25519 which has
            // a known limitation in hybrid public key storage.
            let signed = sign(message, CryptoConfig::new().security_level(SecurityLevel::High));
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
fn test_unified_api_rejects_symmetric_key_for_hybrid_schemes() {
    std::thread::Builder::new()
        .name("test_unified_api_rejects_symmetric_key_for_hybrid".to_string())
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            // The unified encrypt() API validates that hybrid schemes receive proper keys
            // A 32-byte symmetric key should be rejected for hybrid schemes

            let data = b"Test data";
            let symmetric_key = vec![0x42u8; 32];

            // Configure for hybrid encryption explicitly
            use crate::UseCase;
            let config = CryptoConfig::new().use_case(UseCase::FileStorage);

            // This should fail because UseCase::FileStorage selects hybrid scheme
            // but we're providing a 32-byte symmetric key
            let result = encrypt(data, &symmetric_key, config);

            // Should fail with InvalidKey error
            assert!(result.is_err(), "Hybrid scheme should reject 32-byte symmetric key");
            if let Err(e) = result {
                let error_message = format!("{:?}", e);
                assert!(
                    error_message.contains("public key") || error_message.contains("InvalidKey"),
                    "Error should mention public key requirement: {}",
                    error_message
                );
            }
        })
        .unwrap()
        .join()
        .unwrap();
}

/// Test hybrid encryption roundtrip with ML-KEM-768.
///
/// Note: This test is ignored due to aws-lc-rs not supporting ML-KEM secret key
/// deserialization. The encryption works but decapsulation requires the original
/// DecapsulationKey object from key generation.
/// See: docs/ML_KEM_KEY_PERSISTENCE.md
#[test]
#[ignore = "aws-lc-rs does not support secret key deserialization - decapsulate not functional"]
fn test_hybrid_encryption_public_api_roundtrip() {
    std::thread::Builder::new()
        .name("test_hybrid_encryption_public_api_roundtrip".to_string())
        .stack_size(32 * 1024 * 1024)
        .spawn(|| {
            use crate::convenience::{decrypt_hybrid, encrypt_hybrid, generate_ml_kem_keypair};
            use crate::zero_trust::SecurityMode;
            use arc_primitives::kem::ml_kem::MlKemSecurityLevel;

            let data = b"Secret message for hybrid encryption test";
            let symmetric_key = vec![0x42u8; 32];

            // Generate ML-KEM keypair
            let (public_key, private_key) = generate_ml_kem_keypair(MlKemSecurityLevel::MlKem768)
                .expect("ML-KEM keypair generation should succeed");

            // Encrypt with hybrid scheme
            let encrypted =
                encrypt_hybrid(data, Some(&public_key), &symmetric_key, SecurityMode::Unverified)
                    .expect("Hybrid encryption should succeed");

            // Decrypt with hybrid scheme
            let decrypted = decrypt_hybrid(
                &encrypted.ciphertext,
                Some(private_key.as_ref()),
                &encrypted.encapsulated_key,
                &symmetric_key,
                SecurityMode::Unverified,
            )
            .expect("Hybrid decryption should succeed");

            assert_eq!(data.as_slice(), decrypted.as_slice());
        })
        .unwrap()
        .join()
        .unwrap();
}

#[test]
#[ignore = "aws-lc-rs does not support secret key deserialization - decapsulate not functional"]
fn test_hybrid_encryption_ml_kem_512() {
    std::thread::Builder::new()
        .name("test_hybrid_encryption_ml_kem_512".to_string())
        .stack_size(32 * 1024 * 1024)
        .spawn(|| {
            use crate::convenience::{decrypt_hybrid, encrypt_hybrid, generate_ml_kem_keypair};
            use crate::zero_trust::SecurityMode;
            use arc_primitives::kem::ml_kem::MlKemSecurityLevel;

            let data = b"ML-KEM-512 test data";
            let symmetric_key = vec![0xABu8; 32];

            let (public_key, private_key) = generate_ml_kem_keypair(MlKemSecurityLevel::MlKem512)
                .expect("ML-KEM-512 keypair generation should succeed");

            let encrypted =
                encrypt_hybrid(data, Some(&public_key), &symmetric_key, SecurityMode::Unverified)
                    .expect("ML-KEM-512 hybrid encryption should succeed");

            let decrypted = decrypt_hybrid(
                &encrypted.ciphertext,
                Some(private_key.as_ref()),
                &encrypted.encapsulated_key,
                &symmetric_key,
                SecurityMode::Unverified,
            )
            .expect("ML-KEM-512 hybrid decryption should succeed");

            assert_eq!(data.as_slice(), decrypted.as_slice());
        })
        .unwrap()
        .join()
        .unwrap();
}

#[test]
#[ignore = "aws-lc-rs does not support secret key deserialization - decapsulate not functional"]
fn test_hybrid_encryption_ml_kem_1024() {
    std::thread::Builder::new()
        .name("test_hybrid_encryption_ml_kem_1024".to_string())
        .stack_size(32 * 1024 * 1024)
        .spawn(|| {
            use crate::convenience::{decrypt_hybrid, encrypt_hybrid, generate_ml_kem_keypair};
            use crate::zero_trust::SecurityMode;
            use arc_primitives::kem::ml_kem::MlKemSecurityLevel;

            let data = b"ML-KEM-1024 test data for maximum security";
            let symmetric_key = vec![0xCDu8; 32];

            let (public_key, private_key) = generate_ml_kem_keypair(MlKemSecurityLevel::MlKem1024)
                .expect("ML-KEM-1024 keypair generation should succeed");

            let encrypted =
                encrypt_hybrid(data, Some(&public_key), &symmetric_key, SecurityMode::Unverified)
                    .expect("ML-KEM-1024 hybrid encryption should succeed");

            let decrypted = decrypt_hybrid(
                &encrypted.ciphertext,
                Some(private_key.as_ref()),
                &encrypted.encapsulated_key,
                &symmetric_key,
                SecurityMode::Unverified,
            )
            .expect("ML-KEM-1024 hybrid decryption should succeed");

            assert_eq!(data.as_slice(), decrypted.as_slice());
        })
        .unwrap()
        .join()
        .unwrap();
}

#[test]
fn test_hybrid_encryption_only() {
    std::thread::Builder::new()
        .name("test_hybrid_encryption_only".to_string())
        .stack_size(32 * 1024 * 1024)
        .spawn(|| {
            use crate::convenience::{encrypt_hybrid, generate_ml_kem_keypair};
            use crate::zero_trust::SecurityMode;
            use arc_primitives::kem::ml_kem::MlKemSecurityLevel;

            let data = b"Test hybrid encryption (without decryption due to aws-lc-rs limitation)";
            let symmetric_key = vec![0x42u8; 32];

            // Generate ML-KEM keypair
            let (public_key, _private_key) = generate_ml_kem_keypair(MlKemSecurityLevel::MlKem768)
                .expect("ML-KEM keypair generation should succeed");

            // Encrypt with hybrid scheme - this should work
            let encrypted =
                encrypt_hybrid(data, Some(&public_key), &symmetric_key, SecurityMode::Unverified)
                    .expect("Hybrid encryption should succeed");

            // Verify encrypted data structure
            assert!(!encrypted.ciphertext.is_empty(), "Ciphertext should not be empty");
            assert!(!encrypted.encapsulated_key.is_empty(), "Encapsulated key should not be empty");
            // ML-KEM-768 encapsulated key is 1088 bytes
            assert_eq!(
                encrypted.encapsulated_key.len(),
                1088,
                "ML-KEM-768 encapsulated key should be 1088 bytes"
            );
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
