#![deny(unsafe_code)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::panic)]
#![allow(clippy::indexing_slicing)]
#![allow(missing_docs)]

//! Coverage tests for kem_hybrid.rs error paths and edge cases.

use latticearc::hybrid::kem_hybrid::{
    HybridKemError, HybridKemPublicKey, HybridSharedSecretInputs, decapsulate,
    derive_hybrid_shared_secret, encapsulate, generate_keypair,
};
use latticearc::primitives::kem::ml_kem::MlKemSecurityLevel;
use subtle::ConstantTimeEq;

// ============================================================================
// derive_hybrid_shared_secret error paths
// ============================================================================

#[test]
fn test_derive_rejects_wrong_mlkem_ss_length_fails() {
    let ml_kem_ss = vec![0u8; 16]; // Should be 32
    let ecdh_ss = vec![0u8; 32];
    let result = derive_hybrid_shared_secret(HybridSharedSecretInputs {
        ml_kem_ss: &ml_kem_ss,
        ecdh_ss: &ecdh_ss,
        static_pk: &[0u8; 32],
        ephemeral_pk: &[0u8; 32],
        kem_ct: &[],
    });
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
fn test_derive_rejects_wrong_ecdh_ss_length_fails() {
    let ml_kem_ss = vec![0u8; 32];
    let ecdh_ss = vec![0u8; 16]; // Should be 32
    let result = derive_hybrid_shared_secret(HybridSharedSecretInputs {
        ml_kem_ss: &ml_kem_ss,
        ecdh_ss: &ecdh_ss,
        static_pk: &[0u8; 32],
        ephemeral_pk: &[0u8; 32],
        kem_ct: &[],
    });
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
fn test_derive_rejects_empty_mlkem_ss_fails() {
    let result = derive_hybrid_shared_secret(HybridSharedSecretInputs {
        ml_kem_ss: &[],
        ecdh_ss: &[0u8; 32],
        static_pk: &[0u8; 32],
        ephemeral_pk: &[0u8; 32],
        kem_ct: &[],
    });
    assert!(result.is_err());
}

#[test]
fn test_derive_rejects_empty_ecdh_ss_fails() {
    let result = derive_hybrid_shared_secret(HybridSharedSecretInputs {
        ml_kem_ss: &[0u8; 32],
        ecdh_ss: &[],
        static_pk: &[0u8; 32],
        ephemeral_pk: &[0u8; 32],
        kem_ct: &[],
    });
    assert!(result.is_err());
}

#[test]
fn test_derive_accepts_valid_inputs_succeeds() {
    let ml_kem_ss = vec![0xAAu8; 32];
    let ecdh_ss = vec![0xBBu8; 32];
    let static_pk = vec![0xCCu8; 32];
    let ephemeral_pk = vec![0xDDu8; 32];
    let result = derive_hybrid_shared_secret(HybridSharedSecretInputs {
        ml_kem_ss: &ml_kem_ss,
        ecdh_ss: &ecdh_ss,
        static_pk: &static_pk,
        ephemeral_pk: &ephemeral_pk,
        kem_ct: &[],
    });
    assert!(result.is_ok());
    let secret = result.unwrap();
    assert_eq!(secret.len(), 64);
}

#[test]
fn test_derive_deterministic_is_deterministic() {
    let ml_kem_ss = vec![1u8; 32];
    let ecdh_ss = vec![2u8; 32];
    let static_pk = vec![3u8; 32];
    let ephemeral_pk = vec![4u8; 32];
    let s1 = derive_hybrid_shared_secret(HybridSharedSecretInputs {
        ml_kem_ss: &ml_kem_ss,
        ecdh_ss: &ecdh_ss,
        static_pk: &static_pk,
        ephemeral_pk: &ephemeral_pk,
        kem_ct: &[],
    })
    .unwrap();
    let s2 = derive_hybrid_shared_secret(HybridSharedSecretInputs {
        ml_kem_ss: &ml_kem_ss,
        ecdh_ss: &ecdh_ss,
        static_pk: &static_pk,
        ephemeral_pk: &ephemeral_pk,
        kem_ct: &[],
    })
    .unwrap();
    assert!(bool::from(s1.ct_eq(&s2)));
}

#[test]
fn test_derive_different_inputs_different_outputs_succeeds() {
    let ml_kem_ss_a = vec![1u8; 32];
    let ml_kem_ss_b = vec![2u8; 32];
    let ecdh_ss = vec![0u8; 32];
    let pk = vec![0u8; 32];
    let s_a = derive_hybrid_shared_secret(HybridSharedSecretInputs {
        ml_kem_ss: &ml_kem_ss_a,
        ecdh_ss: &ecdh_ss,
        static_pk: &pk,
        ephemeral_pk: &pk,
        kem_ct: &[],
    })
    .unwrap();
    let s_b = derive_hybrid_shared_secret(HybridSharedSecretInputs {
        ml_kem_ss: &ml_kem_ss_b,
        ecdh_ss: &ecdh_ss,
        static_pk: &pk,
        ephemeral_pk: &pk,
        kem_ct: &[],
    })
    .unwrap();
    assert!(!bool::from(s_a.ct_eq(&s_b)));
}

#[test]
fn test_derive_context_binding_succeeds() {
    let ml_kem_ss = vec![5u8; 32];
    let ecdh_ss = vec![6u8; 32];
    let pk_a = vec![7u8; 32];
    let pk_b = vec![8u8; 32];
    // Different static PKs should yield different secrets (context binding)
    let s_a = derive_hybrid_shared_secret(HybridSharedSecretInputs {
        ml_kem_ss: &ml_kem_ss,
        ecdh_ss: &ecdh_ss,
        static_pk: &pk_a,
        ephemeral_pk: &pk_a,
        kem_ct: &[],
    })
    .unwrap();
    let s_b = derive_hybrid_shared_secret(HybridSharedSecretInputs {
        ml_kem_ss: &ml_kem_ss,
        ecdh_ss: &ecdh_ss,
        static_pk: &pk_b,
        ephemeral_pk: &pk_b,
        kem_ct: &[],
    })
    .unwrap();
    assert!(!bool::from(s_a.ct_eq(&s_b)));
}

// ============================================================================
// encapsulate() error paths
// ============================================================================

#[test]
fn test_encapsulate_rejects_wrong_ecdh_pk_length_fails() {
    let pk = HybridKemPublicKey::new(
        vec![0u8; 1184],
        vec![0u8; 16], // Should be 32
        MlKemSecurityLevel::MlKem768,
    );
    let result = encapsulate(&pk);
    assert!(result.is_err());
    // Pattern 6 (TOFU follow-up): the ECDH PK length pre-check now
    // collapses into the same opaque variant as every other
    // encapsulate failure to remove the wire-controlled length oracle.
    assert!(matches!(result.unwrap_err(), HybridKemError::EncapsulationFailed));
}

#[test]
fn test_encapsulate_rejects_empty_ecdh_pk_fails() {
    let pk = HybridKemPublicKey::new(vec![0u8; 1184], vec![], MlKemSecurityLevel::MlKem768);
    let result = encapsulate(&pk);
    assert!(result.is_err());
}

// ============================================================================
// decapsulate() error paths
// ============================================================================

#[test]
fn test_decapsulate_rejects_wrong_ecdh_pk_length_fails() {
    let (_pk, sk) = generate_keypair().unwrap();

    let enc = latticearc::hybrid::kem_hybrid::EncapsulatedKey::new(
        vec![0u8; 1088],
        vec![0u8; 16], // Should be 32
        latticearc::SecretBytes::zero(),
    );
    let result = decapsulate(&sk, &enc);
    assert!(result.is_err());
    // Pattern 6 opacity: every decap-side failure (length, KEM, ECDH, KDF)
    // collapses to `DecapsulationFailed` so the API cannot be turned into
    // a length / padding / MAC oracle.
    match result.unwrap_err() {
        HybridKemError::DecapsulationFailed => {}
        other => panic!("Expected DecapsulationFailed, got {:?}", other),
    }
}

// ============================================================================
// HybridKemError Display coverage
// ============================================================================

#[test]
fn test_error_display_ml_kem_fails() {
    let err = HybridKemError::MlKemError("test".to_string());
    assert!(format!("{}", err).contains("ML-KEM"));
}

#[test]
fn test_error_display_ecdh_fails() {
    let err = HybridKemError::EcdhError("test".to_string());
    assert!(format!("{}", err).contains("ECDH"));
}

#[test]
fn test_error_display_kdf_fails() {
    let err = HybridKemError::KdfError("test".to_string());
    assert!(format!("{}", err).contains("Key derivation"));
}

#[test]
fn test_error_display_invalid_key_fails() {
    let err = HybridKemError::InvalidKeyMaterial("test".to_string());
    assert!(format!("{}", err).contains("Invalid key material"));
}

#[test]
fn test_error_display_crypto_fails() {
    let err = HybridKemError::CryptoError("test".to_string());
    assert!(format!("{}", err).contains("Cryptographic operation"));
}

#[test]
fn test_error_clone_round_trips() {
    let err1 = HybridKemError::MlKemError("a".to_string());
    let err2 = err1.clone();
    assert_eq!(err1.to_string(), err2.to_string());
    assert!(matches!(err2, HybridKemError::MlKemError(_)));

    let err3 = HybridKemError::EcdhError("a".to_string());
    assert!(matches!(err3, HybridKemError::EcdhError(_)));
}

#[test]
fn test_error_debug_fails() {
    let err = HybridKemError::KdfError("info".to_string());
    let debug = format!("{:?}", err);
    assert!(debug.contains("KdfError"));
}

// ============================================================================
// HybridKemPublicKey and HybridKemSecretKey coverage
// ============================================================================

#[test]
fn test_public_key_clone_and_debug_succeeds() {
    let (pk, _sk) = generate_keypair().unwrap();

    let cloned = pk.clone();
    assert_eq!(cloned.ml_kem_pk(), pk.ml_kem_pk());
    assert_eq!(cloned.ecdh_pk(), pk.ecdh_pk());

    let debug = format!("{:?}", pk);
    assert!(debug.contains("HybridKemPublicKey"));
}

#[test]
fn test_secret_key_debug_succeeds() {
    let (_pk, sk) = generate_keypair().unwrap();

    let debug = format!("{:?}", sk);
    assert!(debug.contains("HybridKemSecretKey"));
}

#[test]
fn test_secret_key_accessors_succeeds() {
    let (pk, sk) = generate_keypair().unwrap();

    // SK's public key bytes should match PK
    assert_eq!(sk.ml_kem_pk_bytes(), pk.ml_kem_pk());
    assert_eq!(sk.ecdh_public_key_bytes(), pk.ecdh_pk());
}

// ============================================================================
// EncapsulatedKey coverage
// ============================================================================

#[test]
fn test_encapsulated_key_debug_succeeds() {
    let (pk, _sk) = generate_keypair().unwrap();
    let enc = encapsulate(&pk).unwrap();

    let debug = format!("{:?}", enc);
    assert!(debug.contains("EncapsulatedKey"));
}

#[test]
fn test_encapsulated_key_shared_secret_length_has_correct_size() {
    let (pk, _sk) = generate_keypair().unwrap();
    let enc = encapsulate(&pk).unwrap();
    assert_eq!(enc.expose_secret().len(), 64, "Hybrid shared secret should be 64 bytes");
    assert_eq!(enc.ml_kem_ct().len(), 1088, "ML-KEM ciphertext should be 1088 bytes");
    assert_eq!(enc.ecdh_pk().len(), 32, "Ephemeral ECDH PK should be 32 bytes");
}

// ============================================================================
// Public-API roundtrip — round-10 audit follow-up #12.
//
// kem_hybrid had a roundtrip test at `latticearc/src/hybrid/kem_hybrid.rs`
// inside `#[cfg(test)] mod tests` — that exercises the *internal* call
// path. The integration-test crate boundary here exercises the *public*
// path (only `pub` items are reachable), catching regressions where a
// re-export breaks or a `pub(crate)` accidentally hides a symbol used
// by the internal test but not by downstream consumers.
// ============================================================================

#[test]
fn test_public_api_encapsulate_decapsulate_roundtrip() {
    let (pk, sk) = generate_keypair().unwrap();

    let enc = encapsulate(&pk).unwrap();
    let dec = decapsulate(&sk, &enc).unwrap();

    assert!(
        bool::from(dec.expose_secret().ct_eq(enc.expose_secret())),
        "Hybrid KEM roundtrip must agree on the shared secret"
    );
}

#[test]
fn test_public_api_two_encapsulations_diverge() {
    let (pk, sk) = generate_keypair().unwrap();

    let enc1 = encapsulate(&pk).unwrap();
    let enc2 = encapsulate(&pk).unwrap();

    let dec1 = decapsulate(&sk, &enc1).unwrap();
    let dec2 = decapsulate(&sk, &enc2).unwrap();

    // Shared secrets MUST differ between independent encapsulations
    // (each pulls fresh ML-KEM randomness + a fresh ephemeral ECDH key).
    assert!(
        !bool::from(dec1.expose_secret().ct_eq(dec2.expose_secret())),
        "Independent encapsulations must yield distinct shared secrets"
    );
}
