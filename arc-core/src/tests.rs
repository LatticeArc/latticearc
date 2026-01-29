#![deny(unsafe_code)]
// Tests are allowed to use unwrap/expect for simplicity
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::panic)]
// Tests use _unverified functions for simplicity (no session management needed)

use crate::*;

#[test]
fn test_basic_encryption() {
    std::thread::Builder::new()
        .name("test_basic_encryption".to_string())
        .stack_size(32 * 1024 * 1024)
        .spawn(|| {
            let data = b"Hello, LatticeArc Core!";
            let key = vec![1u8; 32];

            // Test encryption with explicit symmetric scheme
            // Note: Default encryption uses hybrid PQ schemes which require public keys.
            // For symmetric encryption with a 32-byte key, explicitly request Symmetric scheme.
            let config = EncryptionConfig::new().with_scheme(CryptoScheme::Symmetric);
            let encrypted = encrypt_with_config_unverified(data, &config, &key)
                .expect("Encryption should succeed");

            // Test decryption
            let decrypted =
                decrypt_unverified(&encrypted, &key).expect("Decryption should succeed");

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

            // Test signing
            let signed = sign_unverified(message).expect("Signing should succeed");

            // Test verification
            let verified = verify_unverified(&signed).expect("Verification should succeed");

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

            let data = b"Hello, Zero Trust!";
            let key = vec![1u8; 32];

            // Test encryption with session using SecurityMode
            let config = EncryptionConfig::new().with_scheme(CryptoScheme::Symmetric);
            let encrypted =
                encrypt_with_config(data, &config, &key, SecurityMode::Verified(&session))
                    .expect("Encryption should succeed");

            // Test decryption with session using SecurityMode
            let decrypted = decrypt(&encrypted, &key, SecurityMode::Verified(&session))
                .expect("Decryption should succeed");

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
fn test_encryption_decryption_with_config() {
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            let data = b"Test data with config";
            // Use symmetric scheme explicitly when providing a 32-byte symmetric key
            // Default scheme selection may choose PQ/hybrid which requires public keys
            let mut config = EncryptionConfig::new().with_scheme(CryptoScheme::Symmetric);
            config.base = config.base.with_security_level(SecurityLevel::High);
            let config = config.with_integrity_check(true);
            let key = vec![2u8; 32];

            let encrypted = encrypt_with_config_unverified(data, &config, &key);
            assert!(encrypted.is_ok(), "Encryption with config failed: {:?}", encrypted.err());

            let encrypted = encrypted.unwrap();
            let decrypted = decrypt_with_config_unverified(&encrypted, &config, &key);
            assert!(decrypted.is_ok(), "Decryption with config failed: {:?}", decrypted.err());

            assert_eq!(data, decrypted.unwrap().as_slice());
        })
        .unwrap()
        .join()
        .unwrap();
}

#[test]
fn test_signature_verification_with_config() {
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            let message = b"Test signature with config";
            let mut config = SignatureConfig::new();
            config.base = config.base.with_security_level(SecurityLevel::High);
            let config = config.with_timestamp(true);

            let signed = sign_with_config_unverified(message, &config);
            assert!(signed.is_ok(), "Signing with config failed: {:?}", signed.err());

            let signed = signed.unwrap();
            let verified = verify_with_config_unverified(message, &signed, &config);
            assert!(verified.is_ok(), "Verification with config failed: {:?}", verified.err());

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
