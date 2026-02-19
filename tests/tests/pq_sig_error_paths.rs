//! Coverage tests for pq_sig.rs error paths — invalid key formats,
//! wrong-length keys, and invalid signatures for ML-DSA, SLH-DSA, FN-DSA.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::cast_precision_loss
)]

use latticearc::primitives::sig::ml_dsa::MlDsaParameterSet;
use latticearc::primitives::sig::slh_dsa::SecurityLevel as SlhDsaSecurityLevel;
use latticearc::unified_api::convenience::*;

// ============================================================
// ML-DSA invalid key error paths
// ============================================================

#[test]
fn test_ml_dsa_44_sign_wrong_sk_length() {
    let bad_sk = vec![0u8; 10]; // too short
    let result = sign_pq_ml_dsa_unverified(b"test", &bad_sk, MlDsaParameterSet::MLDSA44);
    assert!(result.is_err());
}

#[test]
fn test_ml_dsa_44_verify_wrong_pk_length() {
    let bad_pk = vec![0u8; 10]; // too short
    let bad_sig = vec![0u8; 2420]; // ML-DSA-44 signature length
    let result =
        verify_pq_ml_dsa_unverified(b"test", &bad_sig, &bad_pk, MlDsaParameterSet::MLDSA44);
    assert!(result.is_err());
}

#[test]
fn test_ml_dsa_44_verify_wrong_sig_length() {
    let bad_pk = vec![0u8; 1312]; // ML-DSA-44 pk length
    let bad_sig = vec![0u8; 10]; // too short
    let result =
        verify_pq_ml_dsa_unverified(b"test", &bad_sig, &bad_pk, MlDsaParameterSet::MLDSA44);
    assert!(result.is_err());
}

#[test]
fn test_ml_dsa_65_sign_wrong_sk_length() {
    let bad_sk = vec![0u8; 10];
    let result = sign_pq_ml_dsa_unverified(b"test", &bad_sk, MlDsaParameterSet::MLDSA65);
    assert!(result.is_err());
}

#[test]
fn test_ml_dsa_65_verify_wrong_pk_length() {
    let bad_pk = vec![0u8; 10];
    let bad_sig = vec![0u8; 3309]; // ML-DSA-65 signature length
    let result =
        verify_pq_ml_dsa_unverified(b"test", &bad_sig, &bad_pk, MlDsaParameterSet::MLDSA65);
    assert!(result.is_err());
}

#[test]
fn test_ml_dsa_87_sign_wrong_sk_length() {
    let bad_sk = vec![0u8; 10];
    let result = sign_pq_ml_dsa_unverified(b"test", &bad_sk, MlDsaParameterSet::MLDSA87);
    assert!(result.is_err());
}

#[test]
fn test_ml_dsa_87_verify_wrong_pk_length() {
    let bad_pk = vec![0u8; 10];
    let bad_sig = vec![0u8; 4627]; // ML-DSA-87 signature length
    let result =
        verify_pq_ml_dsa_unverified(b"test", &bad_sig, &bad_pk, MlDsaParameterSet::MLDSA87);
    assert!(result.is_err());
}

// ============================================================
// SLH-DSA invalid key error paths
// ============================================================

#[test]
fn test_slh_dsa_128s_sign_wrong_sk_length() {
    let bad_sk = vec![0u8; 10]; // too short (expected 64)
    let result = sign_pq_slh_dsa_unverified(b"test", &bad_sk, SlhDsaSecurityLevel::Shake128s);
    assert!(result.is_err());
}

#[test]
fn test_slh_dsa_128s_verify_wrong_pk_length() {
    let bad_pk = vec![0u8; 10]; // too short (expected 32)
    let bad_sig = vec![0u8; 7856]; // SLH-DSA-128s signature length
    let result =
        verify_pq_slh_dsa_unverified(b"test", &bad_sig, &bad_pk, SlhDsaSecurityLevel::Shake128s);
    assert!(result.is_err());
}

#[test]
fn test_slh_dsa_128s_verify_wrong_sig_length() {
    let bad_pk = vec![0u8; 32]; // SLH-DSA-128s pk length
    let bad_sig = vec![0u8; 10]; // too short
    let result =
        verify_pq_slh_dsa_unverified(b"test", &bad_sig, &bad_pk, SlhDsaSecurityLevel::Shake128s);
    assert!(result.is_err());
}

#[test]
fn test_slh_dsa_192s_sign_wrong_sk_length() {
    let bad_sk = vec![0u8; 10]; // too short (expected 96)
    let result = sign_pq_slh_dsa_unverified(b"test", &bad_sk, SlhDsaSecurityLevel::Shake192s);
    assert!(result.is_err());
}

#[test]
fn test_slh_dsa_192s_verify_wrong_pk_length() {
    let bad_pk = vec![0u8; 10]; // too short (expected 48)
    let bad_sig = vec![0u8; 16224]; // SLH-DSA-192s signature length
    let result =
        verify_pq_slh_dsa_unverified(b"test", &bad_sig, &bad_pk, SlhDsaSecurityLevel::Shake192s);
    assert!(result.is_err());
}

#[test]
fn test_slh_dsa_256s_sign_wrong_sk_length() {
    let bad_sk = vec![0u8; 10]; // too short (expected 128)
    let result = sign_pq_slh_dsa_unverified(b"test", &bad_sk, SlhDsaSecurityLevel::Shake256s);
    assert!(result.is_err());
}

#[test]
fn test_slh_dsa_256s_verify_wrong_pk_length() {
    let bad_pk = vec![0u8; 10]; // too short (expected 64)
    let bad_sig = vec![0u8; 29792]; // SLH-DSA-256s signature length
    let result =
        verify_pq_slh_dsa_unverified(b"test", &bad_sig, &bad_pk, SlhDsaSecurityLevel::Shake256s);
    assert!(result.is_err());
}

// ============================================================
// FN-DSA invalid key error paths
// ============================================================

#[test]
fn test_fn_dsa_sign_invalid_sk_format() {
    let bad_sk = vec![0xFFu8; 100]; // invalid format
    let result = sign_pq_fn_dsa_unverified(b"test", &bad_sk);
    assert!(result.is_err());
}

#[test]
fn test_fn_dsa_verify_invalid_pk_format() {
    let bad_pk = vec![0xFFu8; 100]; // invalid format
    let bad_sig = vec![0u8; 666]; // some arbitrary signature
    let result = verify_pq_fn_dsa_unverified(b"test", &bad_sig, &bad_pk);
    assert!(result.is_err());
}

#[test]
fn test_fn_dsa_verify_invalid_sig_format() {
    // Generate real keypair, then provide bad signature
    let (pk, _sk) = generate_fn_dsa_keypair().unwrap();
    let bad_sig = vec![0xFFu8; 100]; // invalid format
    let result = verify_pq_fn_dsa_unverified(b"test", &bad_sig, &pk);
    assert!(result.is_err());
}
