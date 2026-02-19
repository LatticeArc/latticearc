#![deny(unsafe_code)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::panic)]
#![allow(clippy::indexing_slicing)]
#![allow(missing_docs)]

//! Coverage tests for sig_hybrid.rs error paths and edge cases.

use latticearc::hybrid::sig_hybrid::{
    HybridPublicKey, HybridSecretKey, HybridSignature, HybridSignatureError, generate_keypair,
    sign, verify,
};
use rand::rngs::OsRng;
use zeroize::Zeroizing;

// ============================================================================
// sign() error paths
// ============================================================================

#[test]
fn test_sign_rejects_wrong_ed25519_sk_length() {
    let sk = HybridSecretKey {
        ml_dsa_sk: Zeroizing::new(vec![0u8; 4032]),
        ed25519_sk: Zeroizing::new(vec![0u8; 16]), // Should be 32
    };
    let result = sign(&sk, b"test message");
    assert!(result.is_err());
    match result.unwrap_err() {
        HybridSignatureError::InvalidKeyMaterial(msg) => {
            assert!(msg.contains("32"));
        }
        other => panic!("Expected InvalidKeyMaterial, got {:?}", other),
    }
}

#[test]
fn test_sign_rejects_empty_ed25519_sk() {
    let sk = HybridSecretKey {
        ml_dsa_sk: Zeroizing::new(vec![0u8; 4032]),
        ed25519_sk: Zeroizing::new(vec![]),
    };
    let result = sign(&sk, b"test");
    assert!(result.is_err());
}

// ============================================================================
// verify() error paths
// ============================================================================

#[test]
fn test_verify_rejects_wrong_ed25519_pk_length() {
    let pk = HybridPublicKey {
        ml_dsa_pk: vec![0u8; 1952],
        ed25519_pk: vec![0u8; 16], // Should be 32
    };
    let sig = HybridSignature { ml_dsa_sig: vec![0u8; 3309], ed25519_sig: vec![0u8; 64] };
    let result = verify(&pk, b"test", &sig);
    assert!(result.is_err());
    match result.unwrap_err() {
        HybridSignatureError::InvalidKeyMaterial(msg) => {
            assert!(msg.contains("32"));
        }
        other => panic!("Expected InvalidKeyMaterial, got {:?}", other),
    }
}

#[test]
fn test_verify_rejects_wrong_ed25519_sig_length() {
    let pk = HybridPublicKey { ml_dsa_pk: vec![0u8; 1952], ed25519_pk: vec![0u8; 32] };
    let sig = HybridSignature {
        ml_dsa_sig: vec![0u8; 3309],
        ed25519_sig: vec![0u8; 32], // Should be 64
    };
    let result = verify(&pk, b"test", &sig);
    assert!(result.is_err());
    match result.unwrap_err() {
        HybridSignatureError::InvalidKeyMaterial(msg) => {
            assert!(msg.contains("64"));
        }
        other => panic!("Expected InvalidKeyMaterial, got {:?}", other),
    }
}

#[test]
fn test_verify_rejects_tampered_ml_dsa_signature() {
    let mut rng = OsRng;
    let (pk, sk) = generate_keypair(&mut rng).unwrap();
    let message = b"tamper test message";
    let mut sig = sign(&sk, message).unwrap();

    // Tamper with ML-DSA signature
    if let Some(byte) = sig.ml_dsa_sig.first_mut() {
        *byte ^= 0xFF;
    }

    let result = verify(&pk, message, &sig);
    assert!(result.is_err(), "Tampered ML-DSA signature should fail verification");
}

#[test]
fn test_verify_rejects_tampered_ed25519_signature() {
    let mut rng = OsRng;
    let (pk, sk) = generate_keypair(&mut rng).unwrap();
    let message = b"tamper ed25519 test";
    let mut sig = sign(&sk, message).unwrap();

    // Tamper with Ed25519 signature
    if let Some(byte) = sig.ed25519_sig.first_mut() {
        *byte ^= 0xFF;
    }

    let result = verify(&pk, message, &sig);
    assert!(result.is_err(), "Tampered Ed25519 signature should fail verification");
}

#[test]
fn test_verify_rejects_wrong_message() {
    let mut rng = OsRng;
    let (pk, sk) = generate_keypair(&mut rng).unwrap();
    let sig = sign(&sk, b"original message").unwrap();

    let result = verify(&pk, b"wrong message", &sig);
    assert!(result.is_err(), "Wrong message should fail verification");
}

// ============================================================================
// HybridSignatureError Display coverage
// ============================================================================

#[test]
fn test_error_display_ml_dsa() {
    let err = HybridSignatureError::MlDsaError("test".to_string());
    assert!(format!("{}", err).contains("ML-DSA"));
}

#[test]
fn test_error_display_ed25519() {
    let err = HybridSignatureError::Ed25519Error("test".to_string());
    assert!(format!("{}", err).contains("Ed25519"));
}

#[test]
fn test_error_display_verification() {
    let err = HybridSignatureError::VerificationFailed("test".to_string());
    assert!(format!("{}", err).contains("verification failed"));
}

#[test]
fn test_error_display_invalid_key() {
    let err = HybridSignatureError::InvalidKeyMaterial("test".to_string());
    assert!(format!("{}", err).contains("Invalid key material"));
}

#[test]
fn test_error_display_crypto() {
    let err = HybridSignatureError::CryptoError("test".to_string());
    assert!(format!("{}", err).contains("Cryptographic operation"));
}

#[test]
fn test_error_clone_eq() {
    let err1 = HybridSignatureError::MlDsaError("a".to_string());
    let err2 = err1.clone();
    assert_eq!(err1, err2);

    let err3 = HybridSignatureError::Ed25519Error("a".to_string());
    assert_ne!(err1, err3);
}

#[test]
fn test_error_debug() {
    let err = HybridSignatureError::CryptoError("info".to_string());
    let debug = format!("{:?}", err);
    assert!(debug.contains("CryptoError"));
}

// ============================================================================
// HybridPublicKey coverage
// ============================================================================

#[test]
fn test_public_key_clone_and_debug() {
    let pk = HybridPublicKey { ml_dsa_pk: vec![1u8; 1952], ed25519_pk: vec![2u8; 32] };
    let cloned = pk.clone();
    assert_eq!(cloned.ml_dsa_pk, pk.ml_dsa_pk);
    assert_eq!(cloned.ed25519_pk, pk.ed25519_pk);

    let debug = format!("{:?}", pk);
    assert!(debug.contains("HybridPublicKey"));
}

// ============================================================================
// HybridSecretKey coverage
// ============================================================================

#[test]
fn test_secret_key_byte_accessors() {
    let sk = HybridSecretKey {
        ml_dsa_sk: Zeroizing::new(vec![0xAA; 4032]),
        ed25519_sk: Zeroizing::new(vec![0xBB; 32]),
    };
    assert_eq!(sk.ml_dsa_sk_bytes().len(), 4032);
    assert_eq!(sk.ed25519_sk_bytes().len(), 32);
    assert_eq!(sk.ml_dsa_sk_bytes()[0], 0xAA);
    assert_eq!(sk.ed25519_sk_bytes()[0], 0xBB);
}

#[test]
fn test_secret_key_debug() {
    let sk = HybridSecretKey {
        ml_dsa_sk: Zeroizing::new(vec![0u8; 100]),
        ed25519_sk: Zeroizing::new(vec![0u8; 32]),
    };
    let debug = format!("{:?}", sk);
    assert!(debug.contains("HybridSecretKey"));
}

// ============================================================================
// HybridSignature coverage
// ============================================================================

#[test]
fn test_signature_clone_and_debug() {
    let sig = HybridSignature { ml_dsa_sig: vec![1u8; 100], ed25519_sig: vec![2u8; 64] };
    let cloned = sig.clone();
    assert_eq!(cloned.ml_dsa_sig, sig.ml_dsa_sig);
    assert_eq!(cloned.ed25519_sig, sig.ed25519_sig);

    let debug = format!("{:?}", sig);
    assert!(debug.contains("HybridSignature"));
}

// ============================================================================
// Full sign/verify roundtrip with edge cases
// ============================================================================

#[test]
fn test_sign_verify_empty_message() {
    let mut rng = OsRng;
    let (pk, sk) = generate_keypair(&mut rng).unwrap();
    let sig = sign(&sk, b"").unwrap();
    let valid = verify(&pk, b"", &sig).unwrap();
    assert!(valid);
}

#[test]
fn test_sign_verify_large_message() {
    let mut rng = OsRng;
    let (pk, sk) = generate_keypair(&mut rng).unwrap();
    let large_msg = vec![0xFFu8; 65536]; // 64KB
    let sig = sign(&sk, &large_msg).unwrap();
    let valid = verify(&pk, &large_msg, &sig).unwrap();
    assert!(valid);
}

#[test]
fn test_cross_keypair_rejection() {
    let mut rng = OsRng;
    let (pk_a, sk_a) = generate_keypair(&mut rng).unwrap();
    let (pk_b, _sk_b) = generate_keypair(&mut rng).unwrap();

    let sig = sign(&sk_a, b"test").unwrap();

    // Verify with wrong public key should fail
    let result = verify(&pk_b, b"test", &sig);
    assert!(result.is_err(), "Cross-keypair verification should fail");

    // Verify with correct public key should pass
    let valid = verify(&pk_a, b"test", &sig).unwrap();
    assert!(valid);
}
