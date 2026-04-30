#![deny(unsafe_code)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::panic)]
#![allow(clippy::indexing_slicing)]
#![allow(missing_docs)]

//! Coverage tests for sig_hybrid.rs error paths and edge cases.

use latticearc::hybrid::sig_hybrid::{
    HybridSigPublicKey, HybridSigSecretKey, HybridSignature, HybridSignatureError,
    generate_keypair, sign, verify,
};
use latticearc::primitives::sig::ml_dsa::MlDsaParameterSet;
use zeroize::Zeroizing;

// ============================================================================
// sign() error paths
// ============================================================================

#[test]
fn test_sign_rejects_wrong_ed25519_sk_length_fails() {
    let sk = HybridSigSecretKey::new(
        MlDsaParameterSet::MlDsa65,
        Zeroizing::new(vec![0u8; 4032]),
        Zeroizing::new(vec![0u8; 16]), // Should be 32
    );
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
fn test_sign_rejects_empty_ed25519_sk_fails() {
    let sk = HybridSigSecretKey::new(
        MlDsaParameterSet::MlDsa65,
        Zeroizing::new(vec![0u8; 4032]),
        Zeroizing::new(vec![]),
    );
    let result = sign(&sk, b"test");
    assert!(result.is_err());
}

// ============================================================================
// verify() error paths
// ============================================================================

#[test]
fn test_verify_rejects_wrong_ed25519_pk_length_fails() {
    let pk = HybridSigPublicKey::new(
        MlDsaParameterSet::MlDsa65,
        vec![0u8; 1952],
        vec![0u8; 16], // Should be 32
    );
    let sig = HybridSignature::new(vec![0u8; 3309], vec![0u8; 64]);
    let result = verify(&pk, b"test", &sig);
    // Pattern 6 (#52): verify collapses length mismatches into the
    // bit=0 verify path, so the surviving error is VerificationFailed
    // (no distinguishable InvalidKeyMaterial variant).
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), HybridSignatureError::VerificationFailed(_)));
}

#[test]
fn test_verify_rejects_wrong_ed25519_sig_length_fails() {
    let pk = HybridSigPublicKey::new(MlDsaParameterSet::MlDsa65, vec![0u8; 1952], vec![0u8; 32]);
    // Build with wrong ed25519 length (32 bytes instead of 64) to exercise validation.
    let sig = HybridSignature::new(vec![0u8; 3309], vec![0u8; 32]);
    let result = verify(&pk, b"test", &sig);
    // See note above — Pattern 6 collapse.
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), HybridSignatureError::VerificationFailed(_)));
}

#[test]
fn test_verify_rejects_tampered_ml_dsa_signature_fails() {
    let (pk, sk) = generate_keypair().unwrap();
    let message = b"tamper test message";
    let sig = sign(&sk, message).unwrap();

    // Tamper with ML-DSA signature by reconstructing with the first byte flipped.
    let mut tampered_ml = sig.ml_dsa_sig().to_vec();
    if let Some(byte) = tampered_ml.first_mut() {
        *byte ^= 0xFF;
    }
    let tampered = HybridSignature::new(tampered_ml, sig.ed25519_sig().to_vec());

    let result = verify(&pk, message, &tampered);
    assert!(result.is_err(), "Tampered ML-DSA signature should fail verification");
}

#[test]
fn test_verify_rejects_tampered_ed25519_signature_fails() {
    let (pk, sk) = generate_keypair().unwrap();
    let message = b"tamper ed25519 test";
    let sig = sign(&sk, message).unwrap();

    // Tamper with Ed25519 signature by reconstructing with the first byte flipped.
    let mut tampered_ed = sig.ed25519_sig().to_vec();
    if let Some(byte) = tampered_ed.first_mut() {
        *byte ^= 0xFF;
    }
    let tampered = HybridSignature::new(sig.ml_dsa_sig().to_vec(), tampered_ed);

    let result = verify(&pk, message, &tampered);
    assert!(result.is_err(), "Tampered Ed25519 signature should fail verification");
}

#[test]
fn test_verify_rejects_wrong_message_fails() {
    let (pk, sk) = generate_keypair().unwrap();
    let sig = sign(&sk, b"original message").unwrap();

    let result = verify(&pk, b"wrong message", &sig);
    assert!(result.is_err(), "Wrong message should fail verification");
}

// ============================================================================
// HybridSignatureError Display coverage
// ============================================================================

#[test]
fn test_error_display_ml_dsa_fails() {
    let err = HybridSignatureError::MlDsaError("test".to_string());
    assert!(format!("{}", err).contains("ML-DSA"));
}

#[test]
fn test_error_display_ed25519_fails() {
    let err = HybridSignatureError::Ed25519Error("test".to_string());
    assert!(format!("{}", err).contains("Ed25519"));
}

#[test]
fn test_error_display_verification_fails() {
    let err = HybridSignatureError::VerificationFailed("test".to_string());
    assert!(format!("{}", err).contains("verification failed"));
}

#[test]
fn test_error_display_invalid_key_fails() {
    let err = HybridSignatureError::InvalidKeyMaterial("test".to_string());
    assert!(format!("{}", err).contains("Invalid key material"));
}

#[test]
fn test_error_display_crypto_fails() {
    let err = HybridSignatureError::CryptoError("test".to_string());
    assert!(format!("{}", err).contains("Cryptographic operation"));
}

#[test]
fn test_error_clone_round_trips() {
    let err1 = HybridSignatureError::MlDsaError("a".to_string());
    let err2 = err1.clone();
    assert_eq!(err1.to_string(), err2.to_string());
    assert!(matches!(err2, HybridSignatureError::MlDsaError(_)));

    let err3 = HybridSignatureError::Ed25519Error("a".to_string());
    assert!(matches!(err3, HybridSignatureError::Ed25519Error(_)));
}

#[test]
fn test_error_debug_fails() {
    let err = HybridSignatureError::CryptoError("info".to_string());
    let debug = format!("{:?}", err);
    assert!(debug.contains("CryptoError"));
}

// ============================================================================
// HybridSigPublicKey coverage
// ============================================================================

#[test]
fn test_public_key_clone_and_debug_succeeds() {
    let pk = HybridSigPublicKey::new(MlDsaParameterSet::MlDsa65, vec![1u8; 1952], vec![2u8; 32]);
    let cloned = pk.clone();
    assert_eq!(cloned.ml_dsa_pk(), pk.ml_dsa_pk());
    assert_eq!(cloned.ed25519_pk(), pk.ed25519_pk());
    assert_eq!(cloned.parameter_set(), pk.parameter_set());

    let debug = format!("{:?}", pk);
    assert!(debug.contains("HybridSigPublicKey"));
}

// ============================================================================
// HybridSigSecretKey coverage
// ============================================================================

#[test]
fn test_secret_key_byte_accessors_succeeds() {
    let sk = HybridSigSecretKey::new(
        MlDsaParameterSet::MlDsa65,
        Zeroizing::new(vec![0xAA; 4032]),
        Zeroizing::new(vec![0xBB; 32]),
    );
    assert_eq!(sk.ml_dsa_sk_bytes().len(), 4032);
    assert_eq!(sk.ed25519_sk_bytes().len(), 32);
    assert_eq!(sk.ml_dsa_sk_bytes()[0], 0xAA);
    assert_eq!(sk.ed25519_sk_bytes()[0], 0xBB);
    assert_eq!(sk.parameter_set(), MlDsaParameterSet::MlDsa65);
}

#[test]
fn test_secret_key_debug_succeeds() {
    let sk = HybridSigSecretKey::new(
        MlDsaParameterSet::MlDsa65,
        Zeroizing::new(vec![0u8; 100]),
        Zeroizing::new(vec![0u8; 32]),
    );
    let debug = format!("{:?}", sk);
    assert!(debug.contains("HybridSigSecretKey"));
}

// ============================================================================
// HybridSignature coverage
// ============================================================================

#[test]
fn test_signature_clone_and_debug_succeeds() {
    let sig = HybridSignature::new(vec![1u8; 100], vec![2u8; 64]);
    let cloned = sig.clone();
    assert_eq!(cloned.ml_dsa_sig(), sig.ml_dsa_sig());
    assert_eq!(cloned.ed25519_sig(), sig.ed25519_sig());

    let debug = format!("{:?}", sig);
    assert!(debug.contains("HybridSignature"));
}

// ============================================================================
// Full sign/verify roundtrip with edge cases
// ============================================================================

#[test]
fn test_sign_verify_empty_message_roundtrip() {
    let (pk, sk) = generate_keypair().unwrap();
    let sig = sign(&sk, b"").unwrap();
    let valid = verify(&pk, b"", &sig).unwrap();
    assert!(valid);
}

#[test]
fn test_sign_verify_large_message_roundtrip() {
    let (pk, sk) = generate_keypair().unwrap();
    let large_msg = vec![0xFFu8; 65536]; // 64KB
    let sig = sign(&sk, &large_msg).unwrap();
    let valid = verify(&pk, &large_msg, &sig).unwrap();
    assert!(valid);
}

#[test]
fn test_cross_keypair_rejection_fails() {
    let (pk_a, sk_a) = generate_keypair().unwrap();
    let (pk_b, _sk_b) = generate_keypair().unwrap();

    let sig = sign(&sk_a, b"test").unwrap();

    // Verify with wrong public key should fail
    let result = verify(&pk_b, b"test", &sig);
    assert!(result.is_err(), "Cross-keypair verification should fail");

    // Verify with correct public key should pass
    let valid = verify(&pk_a, b"test", &sig).unwrap();
    assert!(valid);
}
