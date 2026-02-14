//! Coverage tests for _with_config and _with_config_unverified variants
//! across all convenience modules: aes_gcm, ed25519, hashing, pq_kem, keygen, hybrid.
//! (pq_sig variants are tested separately in pq_sig_with_config_coverage.rs)

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::cast_precision_loss,
    deprecated
)]

use arc_core::config::CoreConfig;
use arc_core::convenience::*;
use arc_core::zero_trust::SecurityMode;
use arc_primitives::kem::ml_kem::MlKemSecurityLevel;

// ============================================================
// AES-GCM with_config variants
// ============================================================

#[test]
fn test_aes_gcm_encrypt_decrypt_with_config() {
    let key = vec![0x42u8; 32];
    let plaintext = b"AES-GCM with_config test";
    let config = CoreConfig::default();

    let ciphertext =
        encrypt_aes_gcm_with_config(plaintext, &key, &config, SecurityMode::Unverified).unwrap();
    let decrypted =
        decrypt_aes_gcm_with_config(&ciphertext, &key, &config, SecurityMode::Unverified).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_aes_gcm_encrypt_decrypt_with_config_unverified() {
    let key = vec![0x42u8; 32];
    let plaintext = b"AES-GCM with_config_unverified test";
    let config = CoreConfig::default();

    let ciphertext = encrypt_aes_gcm_with_config_unverified(plaintext, &key, &config).unwrap();
    let decrypted = decrypt_aes_gcm_with_config_unverified(&ciphertext, &key, &config).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_aes_gcm_with_config_invalid_key() {
    let short_key = vec![0x42u8; 10];
    let plaintext = b"test";
    let config = CoreConfig::default();

    let result =
        encrypt_aes_gcm_with_config(plaintext, &short_key, &config, SecurityMode::Unverified);
    assert!(result.is_err());
}

#[test]
fn test_aes_gcm_decrypt_with_config_bad_data() {
    let key = vec![0x42u8; 32];
    let config = CoreConfig::default();
    let bad_ciphertext = vec![0u8; 5]; // Too short to contain nonce+tag

    let result =
        decrypt_aes_gcm_with_config(&bad_ciphertext, &key, &config, SecurityMode::Unverified);
    assert!(result.is_err());
}

// ============================================================
// Ed25519 with_config variants
// ============================================================

#[test]
fn test_ed25519_sign_verify_with_config() {
    let (pk, sk) = generate_keypair().unwrap();
    let message = b"Ed25519 with_config test";
    let config = CoreConfig::default();

    let sig =
        sign_ed25519_with_config(message, sk.as_ref(), &config, SecurityMode::Unverified).unwrap();
    let valid =
        verify_ed25519_with_config(message, &sig, &pk, &config, SecurityMode::Unverified).unwrap();
    assert!(valid);
}

#[test]
fn test_ed25519_sign_verify_with_config_unverified() {
    let (pk, sk) = generate_keypair().unwrap();
    let message = b"Ed25519 with_config_unverified test";
    let config = CoreConfig::default();

    let sig = sign_ed25519_with_config_unverified(message, sk.as_ref(), &config).unwrap();
    let valid = verify_ed25519_with_config_unverified(message, &sig, &pk, &config).unwrap();
    assert!(valid);
}

#[test]
fn test_ed25519_sign_with_config_invalid_key() {
    let bad_sk = vec![0xAA; 5];
    let message = b"test";
    let config = CoreConfig::default();

    let result = sign_ed25519_with_config(message, &bad_sk, &config, SecurityMode::Unverified);
    assert!(result.is_err());
}

#[test]
fn test_ed25519_verify_with_config_invalid() {
    let bad_pk = vec![0xBB; 10];
    let bad_sig = vec![0xCC; 20];
    let message = b"test";
    let config = CoreConfig::default();

    let result =
        verify_ed25519_with_config(message, &bad_sig, &bad_pk, &config, SecurityMode::Unverified);
    assert!(result.is_err());
}

// ============================================================
// Hashing with_config variants
// ============================================================

#[test]
fn test_derive_key_with_config() {
    let password = b"password for config test";
    let salt = b"some salt";
    let config = CoreConfig::default();

    let key =
        derive_key_with_config(password, salt, 32, &config, SecurityMode::Unverified).unwrap();
    assert_eq!(key.len(), 32);
}

#[test]
fn test_derive_key_with_config_unverified() {
    let password = b"password for config unverified";
    let salt = b"some salt";
    let config = CoreConfig::default();

    let key = derive_key_with_config_unverified(password, salt, 32, &config).unwrap();
    assert_eq!(key.len(), 32);
}

#[test]
fn test_hmac_with_config() {
    // hmac_with_config(data, key, config, mode)
    let key = b"hmac key for config test";
    let data = b"data to authenticate";
    let config = CoreConfig::default();

    let mac = hmac_with_config(data, key, &config, SecurityMode::Unverified).unwrap();
    assert!(!mac.is_empty());
}

#[test]
fn test_hmac_with_config_unverified() {
    // hmac_with_config_unverified(key, data, config)
    let key = b"hmac key for config unverified test";
    let data = b"data to authenticate";
    let config = CoreConfig::default();

    let mac = hmac_with_config_unverified(key, data, &config).unwrap();
    assert!(!mac.is_empty());
}

#[test]
fn test_hmac_check_with_config() {
    // hmac_check_with_config(data, key, tag, config, mode)
    let key = b"hmac key for check config test";
    let data = b"data to verify";
    let config = CoreConfig::default();

    let mac = hmac_with_config(data, key, &config, SecurityMode::Unverified).unwrap();
    let valid = hmac_check_with_config(data, key, &mac, &config, SecurityMode::Unverified).unwrap();
    assert!(valid);
}

#[test]
fn test_hmac_check_with_config_unverified() {
    // hmac_check_with_config_unverified(key, data, tag, config)
    let key = b"hmac key for check config unverified";
    let data = b"data to verify";
    let config = CoreConfig::default();

    let mac = hmac_with_config_unverified(key, data, &config).unwrap();
    let valid = hmac_check_with_config_unverified(key, data, &mac, &config).unwrap();
    assert!(valid);
}

#[test]
fn test_hmac_check_with_config_wrong_mac() {
    let key = b"hmac key for wrong mac test";
    let data = b"data to verify";
    let config = CoreConfig::default();

    let wrong_mac = vec![0xAA; 32];
    let valid =
        hmac_check_with_config(data, key, &wrong_mac, &config, SecurityMode::Unverified).unwrap();
    assert!(!valid);
}

// ============================================================
// PQ-KEM with_config variants
// ============================================================

#[test]
fn test_ml_kem_encrypt_with_config() {
    let (pk, _sk) = generate_ml_kem_keypair(MlKemSecurityLevel::MlKem768).unwrap();
    let data = b"ML-KEM with_config test data";
    let config = CoreConfig::default();

    // Encrypt succeeds (exercises the config validation path)
    let encrypted = encrypt_pq_ml_kem_with_config(
        data,
        &pk,
        MlKemSecurityLevel::MlKem768,
        &config,
        SecurityMode::Unverified,
    )
    .unwrap();
    assert!(!encrypted.is_empty());

    // Decrypt with serialized SK fails (FIPS limitation: DecapsulationKey not serializable)
    let result = decrypt_pq_ml_kem_with_config(
        &encrypted,
        _sk.as_ref(),
        MlKemSecurityLevel::MlKem768,
        &config,
        SecurityMode::Unverified,
    );
    assert!(result.is_err());
}

#[test]
fn test_ml_kem_encrypt_with_config_unverified() {
    let (pk, _sk) = generate_ml_kem_keypair(MlKemSecurityLevel::MlKem768).unwrap();
    let data = b"ML-KEM unverified test data";
    let config = CoreConfig::default();

    let encrypted =
        encrypt_pq_ml_kem_with_config_unverified(data, &pk, MlKemSecurityLevel::MlKem768, &config)
            .unwrap();
    assert!(!encrypted.is_empty());

    // Decrypt from serialized SK returns NotImplemented error
    let result = decrypt_pq_ml_kem_with_config_unverified(
        &encrypted,
        _sk.as_ref(),
        MlKemSecurityLevel::MlKem768,
        &config,
    );
    assert!(result.is_err());
}

#[test]
fn test_ml_kem_encrypt_with_config_invalid_pk() {
    let bad_pk = vec![0xAA; 10];
    let data = b"test";
    let config = CoreConfig::default();

    let result = encrypt_pq_ml_kem_with_config(
        data,
        &bad_pk,
        MlKemSecurityLevel::MlKem768,
        &config,
        SecurityMode::Unverified,
    );
    assert!(result.is_err());
}

// ============================================================
// Keygen with_config variants
// ============================================================

#[test]
fn test_generate_keypair_with_config() {
    let config = CoreConfig::default();
    let (pk, sk) = generate_keypair_with_config(&config).unwrap();
    assert!(!pk.is_empty());
    assert!(!sk.is_empty());
}

#[test]
fn test_generate_ml_dsa_keypair_with_config() {
    let config = CoreConfig::default();
    let (pk, sk) = generate_ml_dsa_keypair_with_config(
        arc_primitives::sig::ml_dsa::MlDsaParameterSet::MLDSA44,
        &config,
    )
    .unwrap();
    assert!(!pk.is_empty());
    assert!(!sk.is_empty());
}

#[test]
fn test_generate_slh_dsa_keypair_with_config() {
    std::thread::Builder::new()
        .name("slh_keygen_cfg".to_string())
        .stack_size(32 * 1024 * 1024)
        .spawn(|| {
            let config = CoreConfig::default();
            let (pk, sk) = generate_slh_dsa_keypair_with_config(
                arc_primitives::sig::slh_dsa::SecurityLevel::Shake128s,
                &config,
            )
            .unwrap();
            assert!(!pk.is_empty());
            assert!(!sk.is_empty());
        })
        .unwrap()
        .join()
        .unwrap();
}

#[test]
fn test_generate_fn_dsa_keypair_with_config() {
    std::thread::Builder::new()
        .name("fn_keygen_cfg".to_string())
        .stack_size(32 * 1024 * 1024)
        .spawn(|| {
            let config = CoreConfig::default();
            let (pk, sk) = generate_fn_dsa_keypair_with_config(&config).unwrap();
            assert!(!pk.is_empty());
            assert!(!sk.is_empty());
        })
        .unwrap()
        .join()
        .unwrap();
}

#[test]
fn test_generate_ml_kem_keypair_with_config() {
    let config = CoreConfig::default();
    let (pk, sk) =
        generate_ml_kem_keypair_with_config(MlKemSecurityLevel::MlKem768, &config).unwrap();
    assert!(!pk.is_empty());
    assert!(!sk.is_empty());
}

// ============================================================
// Hybrid signature with_config variants
// ============================================================

#[test]
fn test_hybrid_sign_verify_with_config() {
    let config = CoreConfig::default();
    let (pk, sk) =
        generate_hybrid_signing_keypair_with_config(&config, SecurityMode::Unverified).unwrap();
    let message = b"Hybrid signature with_config test";

    let sig = sign_hybrid_with_config(message, &sk, &config, SecurityMode::Unverified).unwrap();
    let valid =
        verify_hybrid_signature_with_config(message, &sig, &pk, &config, SecurityMode::Unverified)
            .unwrap();
    assert!(valid);
}

// ============================================================
// Hybrid encryption with_config variants
// ============================================================

#[test]
fn test_hybrid_encrypt_decrypt_with_config() {
    let (pk, sk) = generate_hybrid_keypair().unwrap();
    let plaintext = b"Hybrid encryption with_config test";
    let config = CoreConfig::default();

    let result =
        encrypt_hybrid_with_config(plaintext, &pk, &config, SecurityMode::Unverified).unwrap();
    let decrypted =
        decrypt_hybrid_with_config(&result, &sk, &config, SecurityMode::Unverified).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_hybrid_encrypt_decrypt_with_config_unverified() {
    let (pk, sk) = generate_hybrid_keypair().unwrap();
    let plaintext = b"Hybrid encryption unverified";
    let config = CoreConfig::default();

    let result = encrypt_hybrid_with_config_unverified(plaintext, &pk, &config).unwrap();
    let decrypted = decrypt_hybrid_with_config_unverified(&result, &sk, &config).unwrap();
    assert_eq!(decrypted, plaintext);
}
