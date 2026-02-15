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
    clippy::single_match,
    deprecated
)]

use arc_core::convenience::*;
use arc_core::types::{CryptoConfig, EncryptedData, EncryptedMetadata, SignedData, SignedMetadata};
use arc_primitives::sig::ml_dsa::MlDsaParameterSet;
use arc_primitives::sig::slh_dsa::SecurityLevel as SlhDsaSecurityLevel;

// ============================================================
// verify() with SLH-DSA schemes (unreachable via selector)
// ============================================================

#[test]
fn test_verify_slh_dsa_128s_direct() {
    let (pk, sk) = generate_slh_dsa_keypair(SlhDsaSecurityLevel::Shake128s).unwrap();
    let msg = b"SLH-DSA-128s direct verify test";
    let sig = sign_pq_slh_dsa_unverified(msg, sk.as_ref(), SlhDsaSecurityLevel::Shake128s).unwrap();

    let signed = SignedData {
        data: msg.to_vec(),
        metadata: SignedMetadata {
            signature: sig,
            signature_algorithm: "slh-dsa-shake-128s".to_string(),
            public_key: pk,
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
fn test_verify_slh_dsa_192s_direct() {
    let (pk, sk) = generate_slh_dsa_keypair(SlhDsaSecurityLevel::Shake192s).unwrap();
    let msg = b"SLH-DSA-192s direct verify test";
    let sig = sign_pq_slh_dsa_unverified(msg, sk.as_ref(), SlhDsaSecurityLevel::Shake192s).unwrap();

    let signed = SignedData {
        data: msg.to_vec(),
        metadata: SignedMetadata {
            signature: sig,
            signature_algorithm: "slh-dsa-shake-192s".to_string(),
            public_key: pk,
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
fn test_verify_slh_dsa_256s_direct() {
    let (pk, sk) = generate_slh_dsa_keypair(SlhDsaSecurityLevel::Shake256s).unwrap();
    let msg = b"SLH-DSA-256s direct verify test";
    let sig = sign_pq_slh_dsa_unverified(msg, sk.as_ref(), SlhDsaSecurityLevel::Shake256s).unwrap();

    let signed = SignedData {
        data: msg.to_vec(),
        metadata: SignedMetadata {
            signature: sig,
            signature_algorithm: "slh-dsa-shake-256s".to_string(),
            public_key: pk,
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
fn test_verify_fn_dsa_direct() {
    let (pk, sk) = generate_fn_dsa_keypair().unwrap();
    let msg = b"FN-DSA direct verify test";
    let sig = sign_pq_fn_dsa_unverified(msg, sk.as_ref()).unwrap();

    let signed = SignedData {
        data: msg.to_vec(),
        metadata: SignedMetadata {
            signature: sig,
            signature_algorithm: "fn-dsa".to_string(),
            public_key: pk,
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
fn test_verify_pure_ml_dsa_44_direct() {
    let (pk, sk) = generate_ml_dsa_keypair(MlDsaParameterSet::MLDSA44).unwrap();
    let msg = b"Pure ML-DSA-44 verify test";
    let sig = sign_pq_ml_dsa_unverified(msg, sk.as_ref(), MlDsaParameterSet::MLDSA44).unwrap();

    let signed = SignedData {
        data: msg.to_vec(),
        metadata: SignedMetadata {
            signature: sig,
            signature_algorithm: "pq-ml-dsa-44".to_string(),
            public_key: pk,
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
fn test_verify_pure_ml_dsa_65_direct() {
    let (pk, sk) = generate_ml_dsa_keypair(MlDsaParameterSet::MLDSA65).unwrap();
    let msg = b"Pure ML-DSA-65 verify test";
    let sig = sign_pq_ml_dsa_unverified(msg, sk.as_ref(), MlDsaParameterSet::MLDSA65).unwrap();

    let signed = SignedData {
        data: msg.to_vec(),
        metadata: SignedMetadata {
            signature: sig,
            signature_algorithm: "pq-ml-dsa-65".to_string(),
            public_key: pk,
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
            public_key: pk,
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
fn test_decrypt_chacha_scheme_rejected() {
    let key = vec![0x42u8; 32];
    let data = b"Test data for chacha scheme name";
    let config = CryptoConfig::new();

    // Encrypt normally first
    let encrypted = encrypt(data.as_ref(), &key, config.clone()).unwrap();

    // Re-wrap with chacha20-poly1305 scheme name — decrypt now rejects unsupported schemes
    let rewrapped = EncryptedData {
        data: encrypted.data.clone(),
        metadata: EncryptedMetadata {
            nonce: encrypted.metadata.nonce.clone(),
            tag: encrypted.metadata.tag.clone(),
            key_id: None,
        },
        scheme: "chacha20-poly1305".to_string(),
        timestamp: encrypted.timestamp,
    };

    let result = decrypt(&rewrapped, &key, config);
    assert!(result.is_err(), "chacha20-poly1305 should be rejected by decrypt");
}

#[test]
fn test_decrypt_ml_kem_scheme_name_accepted() {
    let key = vec![0x42u8; 32];
    let data = b"Test data for ml-kem scheme name";
    let config = CryptoConfig::new();

    let encrypted = encrypt(data.as_ref(), &key, config.clone()).unwrap();

    // Re-wrap with ml-kem-768 scheme name — accepted because ml-kem-768
    // is in the supported decrypt match (uses AES-256-GCM under the hood)
    let rewrapped = EncryptedData {
        data: encrypted.data.clone(),
        metadata: EncryptedMetadata {
            nonce: encrypted.metadata.nonce.clone(),
            tag: encrypted.metadata.tag.clone(),
            key_id: None,
        },
        scheme: "ml-kem-768".to_string(),
        timestamp: encrypted.timestamp,
    };

    let decrypted = decrypt(&rewrapped, &key, config).unwrap();
    assert_eq!(decrypted, data);
}

#[test]
fn test_decrypt_unknown_scheme_rejected() {
    let key = vec![0x42u8; 32];
    let data = b"Test data for unknown scheme";
    let config = CryptoConfig::new();

    let encrypted = encrypt(data.as_ref(), &key, config.clone()).unwrap();

    // Re-wrap with unknown scheme name — decrypt now rejects unsupported schemes
    let rewrapped = EncryptedData {
        data: encrypted.data.clone(),
        metadata: EncryptedMetadata {
            nonce: encrypted.metadata.nonce.clone(),
            tag: encrypted.metadata.tag.clone(),
            key_id: None,
        },
        scheme: "unknown-scheme".to_string(),
        timestamp: encrypted.timestamp,
    };

    let result = decrypt(&rewrapped, &key, config);
    assert!(result.is_err(), "Unknown scheme should be rejected by decrypt");
}

// ============================================================
// Verify with tampered SLH-DSA signature
// ============================================================

#[test]
fn test_verify_slh_dsa_128s_tampered() {
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
            public_key: pk,
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
