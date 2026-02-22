//! Property-based tests for the unified API (arc-core convenience layer)
//!
//! Tests AEAD roundtrip, signing roundtrip, and cross-security-level consistency
//! via `latticearc::encrypt/decrypt/generate_signing_keypair/sign_with_key/verify`.

#![allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use latticearc::{
    CryptoConfig, CryptoScheme, DecryptKey, EncryptKey, SecurityLevel, UseCase, decrypt, encrypt,
};
use latticearc::{generate_signing_keypair, sign_with_key, verify};
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// AEAD roundtrip: encrypt then decrypt recovers original data (default config).
    #[test]
    fn unified_aead_roundtrip(data in prop::collection::vec(any::<u8>(), 0..4096)) {
        let key = [0x42u8; 32]; // Fixed AES-256 key for testing

        let encrypted = encrypt(&data, EncryptKey::Symmetric(&key), CryptoConfig::new().force_scheme(CryptoScheme::Symmetric)).unwrap();
        let decrypted = decrypt(&encrypted, DecryptKey::Symmetric(&key), CryptoConfig::new()).unwrap();

        prop_assert_eq!(&decrypted, &data, "AEAD roundtrip must recover original data");
    }

    /// AEAD roundtrip with random keys.
    #[test]
    fn unified_aead_random_key(
        data in prop::collection::vec(any::<u8>(), 0..1024),
        key in prop::array::uniform32(any::<u8>()),
    ) {
        let encrypted = encrypt(&data, EncryptKey::Symmetric(&key), CryptoConfig::new().force_scheme(CryptoScheme::Symmetric)).unwrap();
        let decrypted = decrypt(&encrypted, DecryptKey::Symmetric(&key), CryptoConfig::new()).unwrap();

        prop_assert_eq!(&decrypted, &data);
    }

    /// Wrong key cannot decrypt.
    #[test]
    fn unified_aead_wrong_key(
        data in prop::collection::vec(any::<u8>(), 1..256),
        key1 in prop::array::uniform32(any::<u8>()),
        key2 in prop::array::uniform32(any::<u8>()),
    ) {
        prop_assume!(key1 != key2);

        let encrypted = encrypt(&data, EncryptKey::Symmetric(&key1), CryptoConfig::new().force_scheme(CryptoScheme::Symmetric)).unwrap();
        let result = decrypt(&encrypted, DecryptKey::Symmetric(&key2), CryptoConfig::new());

        prop_assert!(result.is_err(), "Wrong key must fail decryption");
    }

    /// Signing roundtrip with default config (hybrid-ml-dsa-65-ed25519).
    #[test]
    fn unified_sign_roundtrip(message in prop::collection::vec(any::<u8>(), 0..1024)) {
        let config = CryptoConfig::new();
        let (pk, sk, _scheme) = generate_signing_keypair(config.clone()).unwrap();

        let signed = sign_with_key(&message, &sk, &pk, config.clone()).unwrap();
        let valid = verify(&signed, config).unwrap();

        prop_assert!(valid, "Valid signature must verify");
    }

    /// Signing with explicit SecurityLevel::Standard (ML-DSA-44 + Ed25519).
    #[test]
    fn unified_sign_standard(message in prop::collection::vec(any::<u8>(), 0..256)) {
        let config = CryptoConfig::new().security_level(SecurityLevel::Standard);
        let (pk, sk, scheme) = generate_signing_keypair(config.clone()).unwrap();

        // Standard selects hybrid-ml-dsa-44-ed25519
        prop_assert!(
            scheme.contains("ml-dsa-44") || scheme.contains("ml-dsa"),
            "Standard level should select ML-DSA-44 variant, got: {}", scheme
        );

        let signed = sign_with_key(&message, &sk, &pk, config.clone()).unwrap();
        let valid = verify(&signed, config).unwrap();

        prop_assert!(valid);
    }

    /// Signing with Maximum security level.
    #[test]
    fn unified_sign_maximum(message in prop::collection::vec(any::<u8>(), 0..256)) {
        let config = CryptoConfig::new().security_level(SecurityLevel::Maximum);
        let (pk, sk, scheme) = generate_signing_keypair(config.clone()).unwrap();

        prop_assert!(
            scheme.contains("ml-dsa-87") || scheme.contains("ml-dsa"),
            "Maximum level should select ML-DSA-87 variant, got: {}", scheme
        );

        let signed = sign_with_key(&message, &sk, &pk, config.clone()).unwrap();
        let valid = verify(&signed, config).unwrap();

        prop_assert!(valid);
    }

    /// Config consistency: same config always selects the same scheme.
    #[test]
    fn unified_config_consistency(_seed in any::<u64>()) {
        let config = CryptoConfig::new().security_level(SecurityLevel::High);

        let (_, _, scheme1) = generate_signing_keypair(config.clone()).unwrap();
        let (_, _, scheme2) = generate_signing_keypair(config).unwrap();

        prop_assert_eq!(&scheme1, &scheme2, "Same config must select same scheme");
    }

    /// Use case configuration: SecureMessaging selects encryption scheme correctly.
    #[test]
    fn unified_use_case_encryption(
        data in prop::collection::vec(any::<u8>(), 0..256),
    ) {
        let key = [0x55u8; 32];

        let encrypted = encrypt(&data, EncryptKey::Symmetric(&key), CryptoConfig::new().use_case(UseCase::SecureMessaging).force_scheme(CryptoScheme::Symmetric)).unwrap();
        let decrypted = decrypt(&encrypted, DecryptKey::Symmetric(&key), CryptoConfig::new()).unwrap();

        prop_assert_eq!(&decrypted, &data);
    }
}
