#![deny(unsafe_code)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::panic)]
#![allow(clippy::indexing_slicing)]
#![allow(missing_docs)]

//! Coverage tests for kem_hybrid.rs error paths and edge cases.

use arc_hybrid::kem_hybrid::{
    HybridKemError, HybridPublicKey, decapsulate, derive_hybrid_shared_secret, encapsulate,
    generate_keypair,
};
use rand::rngs::OsRng;

// ============================================================================
// derive_hybrid_shared_secret error paths
// ============================================================================

#[test]
fn test_derive_rejects_wrong_mlkem_ss_length() {
    let ml_kem_ss = vec![0u8; 16]; // Should be 32
    let ecdh_ss = vec![0u8; 32];
    let result = derive_hybrid_shared_secret(&ml_kem_ss, &ecdh_ss, &[0u8; 32], &[0u8; 32]);
    assert!(result.is_err());
    match result.unwrap_err() {
        HybridKemError::InvalidKeyMaterial(msg) => {
            assert!(msg.contains("ML-KEM"));
            assert!(msg.contains("32"));
        }
        other => panic!("Expected InvalidKeyMaterial, got {:?}", other),
    }
}

#[test]
fn test_derive_rejects_wrong_ecdh_ss_length() {
    let ml_kem_ss = vec![0u8; 32];
    let ecdh_ss = vec![0u8; 16]; // Should be 32
    let result = derive_hybrid_shared_secret(&ml_kem_ss, &ecdh_ss, &[0u8; 32], &[0u8; 32]);
    assert!(result.is_err());
    match result.unwrap_err() {
        HybridKemError::InvalidKeyMaterial(msg) => {
            assert!(msg.contains("ECDH"));
            assert!(msg.contains("32"));
        }
        other => panic!("Expected InvalidKeyMaterial, got {:?}", other),
    }
}

#[test]
fn test_derive_rejects_empty_mlkem_ss() {
    let result = derive_hybrid_shared_secret(&[], &[0u8; 32], &[0u8; 32], &[0u8; 32]);
    assert!(result.is_err());
}

#[test]
fn test_derive_rejects_empty_ecdh_ss() {
    let result = derive_hybrid_shared_secret(&[0u8; 32], &[], &[0u8; 32], &[0u8; 32]);
    assert!(result.is_err());
}

#[test]
fn test_derive_accepts_valid_inputs() {
    let ml_kem_ss = vec![0xAAu8; 32];
    let ecdh_ss = vec![0xBBu8; 32];
    let static_pk = vec![0xCCu8; 32];
    let ephemeral_pk = vec![0xDDu8; 32];
    let result = derive_hybrid_shared_secret(&ml_kem_ss, &ecdh_ss, &static_pk, &ephemeral_pk);
    assert!(result.is_ok());
    let secret = result.unwrap();
    assert_eq!(secret.len(), 64);
}

#[test]
fn test_derive_deterministic() {
    let ml_kem_ss = vec![1u8; 32];
    let ecdh_ss = vec![2u8; 32];
    let static_pk = vec![3u8; 32];
    let ephemeral_pk = vec![4u8; 32];
    let s1 = derive_hybrid_shared_secret(&ml_kem_ss, &ecdh_ss, &static_pk, &ephemeral_pk).unwrap();
    let s2 = derive_hybrid_shared_secret(&ml_kem_ss, &ecdh_ss, &static_pk, &ephemeral_pk).unwrap();
    assert_eq!(s1, s2);
}

#[test]
fn test_derive_different_inputs_different_outputs() {
    let ml_kem_ss_a = vec![1u8; 32];
    let ml_kem_ss_b = vec![2u8; 32];
    let ecdh_ss = vec![0u8; 32];
    let pk = vec![0u8; 32];
    let s_a = derive_hybrid_shared_secret(&ml_kem_ss_a, &ecdh_ss, &pk, &pk).unwrap();
    let s_b = derive_hybrid_shared_secret(&ml_kem_ss_b, &ecdh_ss, &pk, &pk).unwrap();
    assert_ne!(s_a, s_b);
}

#[test]
fn test_derive_context_binding() {
    let ml_kem_ss = vec![5u8; 32];
    let ecdh_ss = vec![6u8; 32];
    let pk_a = vec![7u8; 32];
    let pk_b = vec![8u8; 32];
    // Different static PKs should yield different secrets (context binding)
    let s_a = derive_hybrid_shared_secret(&ml_kem_ss, &ecdh_ss, &pk_a, &pk_a).unwrap();
    let s_b = derive_hybrid_shared_secret(&ml_kem_ss, &ecdh_ss, &pk_b, &pk_b).unwrap();
    assert_ne!(s_a, s_b);
}

// ============================================================================
// encapsulate() error paths
// ============================================================================

#[test]
fn test_encapsulate_rejects_wrong_ecdh_pk_length() {
    let mut rng = OsRng;
    let pk = HybridPublicKey {
        ml_kem_pk: vec![0u8; 1184],
        ecdh_pk: vec![0u8; 16], // Should be 32
    };
    let result = encapsulate(&mut rng, &pk);
    assert!(result.is_err());
    match result.unwrap_err() {
        HybridKemError::InvalidKeyMaterial(msg) => {
            assert!(msg.contains("32") || msg.contains("ECDH"));
        }
        other => panic!("Expected InvalidKeyMaterial, got {:?}", other),
    }
}

#[test]
fn test_encapsulate_rejects_empty_ecdh_pk() {
    let mut rng = OsRng;
    let pk = HybridPublicKey { ml_kem_pk: vec![0u8; 1184], ecdh_pk: vec![] };
    let result = encapsulate(&mut rng, &pk);
    assert!(result.is_err());
}

// ============================================================================
// decapsulate() error paths
// ============================================================================

#[test]
fn test_decapsulate_rejects_wrong_ecdh_pk_length() {
    let mut rng = OsRng;
    let (_pk, sk) = generate_keypair(&mut rng).unwrap();

    let enc = arc_hybrid::kem_hybrid::EncapsulatedKey {
        ml_kem_ct: vec![0u8; 1088],
        ecdh_pk: vec![0u8; 16], // Should be 32
        shared_secret: zeroize::Zeroizing::new(vec![]),
    };
    let result = decapsulate(&sk, &enc);
    assert!(result.is_err());
    match result.unwrap_err() {
        HybridKemError::InvalidKeyMaterial(msg) => {
            assert!(msg.contains("32") || msg.contains("ECDH"));
        }
        other => panic!("Expected InvalidKeyMaterial, got {:?}", other),
    }
}

// ============================================================================
// HybridKemError Display coverage
// ============================================================================

#[test]
fn test_error_display_ml_kem() {
    let err = HybridKemError::MlKemError("test".to_string());
    assert!(format!("{}", err).contains("ML-KEM"));
}

#[test]
fn test_error_display_ecdh() {
    let err = HybridKemError::EcdhError("test".to_string());
    assert!(format!("{}", err).contains("ECDH"));
}

#[test]
fn test_error_display_kdf() {
    let err = HybridKemError::KdfError("test".to_string());
    assert!(format!("{}", err).contains("Key derivation"));
}

#[test]
fn test_error_display_invalid_key() {
    let err = HybridKemError::InvalidKeyMaterial("test".to_string());
    assert!(format!("{}", err).contains("Invalid key material"));
}

#[test]
fn test_error_display_crypto() {
    let err = HybridKemError::CryptoError("test".to_string());
    assert!(format!("{}", err).contains("Cryptographic operation"));
}

#[test]
fn test_error_clone_eq() {
    let err1 = HybridKemError::MlKemError("a".to_string());
    let err2 = err1.clone();
    assert_eq!(err1, err2);

    let err3 = HybridKemError::EcdhError("a".to_string());
    assert_ne!(err1, err3);
}

#[test]
fn test_error_debug() {
    let err = HybridKemError::KdfError("info".to_string());
    let debug = format!("{:?}", err);
    assert!(debug.contains("KdfError"));
}

// ============================================================================
// HybridPublicKey and HybridSecretKey coverage
// ============================================================================

#[test]
fn test_public_key_clone_and_debug() {
    let mut rng = OsRng;
    let (pk, _sk) = generate_keypair(&mut rng).unwrap();

    let cloned = pk.clone();
    assert_eq!(cloned.ml_kem_pk, pk.ml_kem_pk);
    assert_eq!(cloned.ecdh_pk, pk.ecdh_pk);

    let debug = format!("{:?}", pk);
    assert!(debug.contains("HybridPublicKey"));
}

#[test]
fn test_secret_key_debug() {
    let mut rng = OsRng;
    let (_pk, sk) = generate_keypair(&mut rng).unwrap();

    let debug = format!("{:?}", sk);
    assert!(debug.contains("HybridSecretKey"));
}

#[test]
fn test_secret_key_accessors() {
    let mut rng = OsRng;
    let (pk, sk) = generate_keypair(&mut rng).unwrap();

    // SK's public key bytes should match PK
    assert_eq!(sk.ml_kem_pk_bytes(), pk.ml_kem_pk);
    assert_eq!(sk.ecdh_public_key_bytes(), pk.ecdh_pk);
}

// ============================================================================
// EncapsulatedKey coverage
// ============================================================================

#[test]
fn test_encapsulated_key_debug() {
    let mut rng = OsRng;
    let (pk, _sk) = generate_keypair(&mut rng).unwrap();
    let enc = encapsulate(&mut rng, &pk).unwrap();

    let debug = format!("{:?}", enc);
    assert!(debug.contains("EncapsulatedKey"));
}

#[test]
fn test_encapsulated_key_shared_secret_length() {
    let mut rng = OsRng;
    let (pk, _sk) = generate_keypair(&mut rng).unwrap();
    let enc = encapsulate(&mut rng, &pk).unwrap();
    assert_eq!(enc.shared_secret.len(), 64, "Hybrid shared secret should be 64 bytes");
    assert_eq!(enc.ml_kem_ct.len(), 1088, "ML-KEM ciphertext should be 1088 bytes");
    assert_eq!(enc.ecdh_pk.len(), 32, "Ephemeral ECDH PK should be 32 bytes");
}
