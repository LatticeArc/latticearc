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
    let sig = sign_pq_slh_dsa_unverified(msg, sk.as_ref(), SlhDsaSecurityLevel::Shake128s).unwrap();

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
    let sig = sign_pq_slh_dsa_unverified(msg, sk.as_ref(), SlhDsaSecurityLevel::Shake192s).unwrap();

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
    let sig = sign_pq_slh_dsa_unverified(msg, sk.as_ref(), SlhDsaSecurityLevel::Shake256s).unwrap();

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
    let sig = sign_pq_fn_dsa_unverified(msg, sk.as_ref(), FnDsaSecurityLevel::Level512).unwrap();

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
    let sig = sign_pq_ml_dsa_unverified(msg, sk.as_ref(), MlDsaParameterSet::MlDsa44).unwrap();

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
    let sig = sign_pq_ml_dsa_unverified(msg, sk.as_ref(), MlDsaParameterSet::MlDsa65).unwrap();

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
// ============================================================

#[test]
fn test_verify_ed25519_scheme_is_supported() {
    let (pk, sk) = generate_keypair().unwrap();
    let msg = b"Ed25519 verify test";
    let sig = sign_ed25519_unverified(msg, sk.as_ref()).unwrap();

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
    );

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

    // Construct an EncryptedOutput with a hybrid scheme while providing a symmetric key —
    // the type-safe API rejects the key-scheme mismatch before attempting decryption.
    let rewrapped = EncryptedOutput::new(
        EncryptionScheme::HybridMlKem768Aes256Gcm,
        encrypted.ciphertext().to_vec(),
        encrypted.nonce().to_vec(),
        encrypted.tag().to_vec(),
        None,
        encrypted.timestamp(),
        None,
    );

    let result = decrypt(&rewrapped, DecryptKey::Symmetric(&key), config);
    assert!(result.is_err(), "Hybrid scheme with symmetric key should be rejected by decrypt");
}

// ============================================================
// Verify with tampered SLH-DSA signature
// ============================================================

#[test]
fn test_verify_slh_dsa_128s_tampered_fails() {
    let (pk, sk) = generate_slh_dsa_keypair(SlhDsaSecurityLevel::Shake128s).unwrap();
    let msg = b"SLH-DSA tampered sig test";
    let mut sig =
        sign_pq_slh_dsa_unverified(msg, sk.as_ref(), SlhDsaSecurityLevel::Shake128s).unwrap();

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
