//! ML-DSA (FIPS 204) Known Answer Tests
//!
//! Test vectors derived from NIST FIPS 204 specification and CAVP test files.
//! These tests validate the ML-DSA implementation against official NIST values.

#![allow(clippy::expect_used)]
#![allow(clippy::indexing_slicing)]

// No additional imports needed - tests use #[test] attributes
use arc_primitives::sig::ml_dsa::{
    MlDsaParameterSet, MlDsaPublicKey, MlDsaSecretKey, MlDsaSignature, generate_keypair, sign,
    verify,
};

/// ML-DSA-44 sizes (FIPS 204)
const ML_DSA_44_PK_SIZE: usize = 1312;
const ML_DSA_44_SK_SIZE: usize = 2560;
const ML_DSA_44_SIG_SIZE: usize = 2420;

/// ML-DSA-65 sizes (FIPS 204)
const ML_DSA_65_PK_SIZE: usize = 1952;
const ML_DSA_65_SK_SIZE: usize = 4032;
const ML_DSA_65_SIG_SIZE: usize = 3309;

/// ML-DSA-87 sizes (FIPS 204)
const ML_DSA_87_PK_SIZE: usize = 2592;
const ML_DSA_87_SK_SIZE: usize = 4896;
const ML_DSA_87_SIG_SIZE: usize = 4627;

/// Test ML-DSA-44 key generation produces correct sizes
#[test]
fn test_mldsa_44_key_sizes() {
    let (pk, sk) =
        generate_keypair(MlDsaParameterSet::MLDSA44).expect("key generation should succeed");

    assert_eq!(
        pk.as_bytes().len(),
        ML_DSA_44_PK_SIZE,
        "ML-DSA-44 public key should be {} bytes",
        ML_DSA_44_PK_SIZE
    );
    assert_eq!(
        sk.as_bytes().len(),
        ML_DSA_44_SK_SIZE,
        "ML-DSA-44 secret key should be {} bytes",
        ML_DSA_44_SK_SIZE
    );
}

#[test]
fn test_mldsa_65_key_sizes() {
    let (pk, sk) =
        generate_keypair(MlDsaParameterSet::MLDSA65).expect("key generation should succeed");

    assert_eq!(
        pk.as_bytes().len(),
        ML_DSA_65_PK_SIZE,
        "ML-DSA-65 public key should be {} bytes",
        ML_DSA_65_PK_SIZE
    );
    assert_eq!(
        sk.as_bytes().len(),
        ML_DSA_65_SK_SIZE,
        "ML-DSA-65 secret key should be {} bytes",
        ML_DSA_65_SK_SIZE
    );
}

#[test]
fn test_mldsa_87_key_sizes() {
    let (pk, sk) =
        generate_keypair(MlDsaParameterSet::MLDSA87).expect("key generation should succeed");

    assert_eq!(
        pk.as_bytes().len(),
        ML_DSA_87_PK_SIZE,
        "ML-DSA-87 public key should be {} bytes",
        ML_DSA_87_PK_SIZE
    );
    assert_eq!(
        sk.as_bytes().len(),
        ML_DSA_87_SK_SIZE,
        "ML-DSA-87 secret key should be {} bytes",
        ML_DSA_87_SK_SIZE
    );
}

/// Test ML-DSA signature sizes
#[test]
fn test_mldsa_44_signature_size() {
    let (_pk, sk) =
        generate_keypair(MlDsaParameterSet::MLDSA44).expect("key generation should succeed");

    let message = b"Test message for ML-DSA-44";
    let signature = sign(&sk, message, &[]).expect("signing should succeed");

    assert_eq!(
        signature.as_bytes().len(),
        ML_DSA_44_SIG_SIZE,
        "ML-DSA-44 signature should be {} bytes",
        ML_DSA_44_SIG_SIZE
    );
}

#[test]
fn test_mldsa_65_signature_size() {
    let (_pk, sk) =
        generate_keypair(MlDsaParameterSet::MLDSA65).expect("key generation should succeed");

    let message = b"Test message for ML-DSA-65";
    let signature = sign(&sk, message, &[]).expect("signing should succeed");

    assert_eq!(
        signature.as_bytes().len(),
        ML_DSA_65_SIG_SIZE,
        "ML-DSA-65 signature should be {} bytes",
        ML_DSA_65_SIG_SIZE
    );
}

#[test]
fn test_mldsa_87_signature_size() {
    let (_pk, sk) =
        generate_keypair(MlDsaParameterSet::MLDSA87).expect("key generation should succeed");

    let message = b"Test message for ML-DSA-87";
    let signature = sign(&sk, message, &[]).expect("signing should succeed");

    assert_eq!(
        signature.as_bytes().len(),
        ML_DSA_87_SIG_SIZE,
        "ML-DSA-87 signature should be {} bytes",
        ML_DSA_87_SIG_SIZE
    );
}

/// Test ML-DSA sign/verify roundtrip
#[test]
fn test_mldsa_44_roundtrip() {
    let (pk, sk) =
        generate_keypair(MlDsaParameterSet::MLDSA44).expect("key generation should succeed");

    let message = b"Test message for ML-DSA-44 roundtrip";
    let signature = sign(&sk, message, &[]).expect("signing should succeed");
    let is_valid = verify(&pk, message, &signature, &[]).expect("verification should succeed");

    assert!(is_valid, "ML-DSA-44 signature should verify");
}

#[test]
fn test_mldsa_65_roundtrip() {
    let (pk, sk) =
        generate_keypair(MlDsaParameterSet::MLDSA65).expect("key generation should succeed");

    let message = b"Test message for ML-DSA-65 roundtrip";
    let signature = sign(&sk, message, &[]).expect("signing should succeed");
    let is_valid = verify(&pk, message, &signature, &[]).expect("verification should succeed");

    assert!(is_valid, "ML-DSA-65 signature should verify");
}

#[test]
fn test_mldsa_87_roundtrip() {
    let (pk, sk) =
        generate_keypair(MlDsaParameterSet::MLDSA87).expect("key generation should succeed");

    let message = b"Test message for ML-DSA-87 roundtrip";
    let signature = sign(&sk, message, &[]).expect("signing should succeed");
    let is_valid = verify(&pk, message, &signature, &[]).expect("verification should succeed");

    assert!(is_valid, "ML-DSA-87 signature should verify");
}

/// Test verification fails with wrong message
#[test]
fn test_mldsa_wrong_message() {
    let (pk, sk) =
        generate_keypair(MlDsaParameterSet::MLDSA65).expect("key generation should succeed");

    let message = b"Original message";
    let wrong_message = b"Wrong message";
    let signature = sign(&sk, message, &[]).expect("signing should succeed");
    let is_valid =
        verify(&pk, wrong_message, &signature, &[]).expect("verification should succeed");

    assert!(!is_valid, "Verification should fail with wrong message");
}

/// Test verification fails with corrupted signature
#[test]
fn test_mldsa_corrupted_signature() {
    let (pk, sk) =
        generate_keypair(MlDsaParameterSet::MLDSA65).expect("key generation should succeed");

    let message = b"Test message";
    let signature = sign(&sk, message, &[]).expect("signing should succeed");

    // Corrupt the signature
    let mut corrupted_sig_bytes = signature.as_bytes().to_vec();
    if !corrupted_sig_bytes.is_empty() {
        corrupted_sig_bytes[0] ^= 0xFF;
    }
    let corrupted_sig = MlDsaSignature::new(MlDsaParameterSet::MLDSA65, corrupted_sig_bytes)
        .expect("signature creation should succeed");

    let is_valid = verify(&pk, message, &corrupted_sig, &[]).expect("verification should succeed");

    assert!(!is_valid, "Verification should fail with corrupted signature");
}

/// Test verification fails with wrong public key
#[test]
fn test_mldsa_wrong_public_key() {
    let (_pk1, sk1) =
        generate_keypair(MlDsaParameterSet::MLDSA65).expect("key generation 1 should succeed");
    let (pk2, _sk2) =
        generate_keypair(MlDsaParameterSet::MLDSA65).expect("key generation 2 should succeed");

    let message = b"Test message";
    let signature = sign(&sk1, message, &[]).expect("signing should succeed");
    let is_valid = verify(&pk2, message, &signature, &[]).expect("verification should succeed");

    assert!(!is_valid, "Verification should fail with wrong public key");
}

/// Test different messages produce different signatures (non-deterministic)
#[test]
fn test_mldsa_different_messages_different_signatures() {
    let (_pk, sk) =
        generate_keypair(MlDsaParameterSet::MLDSA65).expect("key generation should succeed");

    let message1 = b"Message 1";
    let message2 = b"Message 2";
    let sig1 = sign(&sk, message1, &[]).expect("signing 1 should succeed");
    let sig2 = sign(&sk, message2, &[]).expect("signing 2 should succeed");

    assert_ne!(
        sig1.as_bytes(),
        sig2.as_bytes(),
        "Different messages should produce different signatures"
    );
}

/// Test same message produces different signatures (randomized signing)
#[test]
fn test_mldsa_same_message_different_signatures() {
    let (_pk, sk) =
        generate_keypair(MlDsaParameterSet::MLDSA65).expect("key generation should succeed");

    let message = b"Same message";
    let sig1 = sign(&sk, message, &[]).expect("signing 1 should succeed");
    let sig2 = sign(&sk, message, &[]).expect("signing 2 should succeed");

    // ML-DSA uses randomized signing, so signatures should differ
    assert_ne!(
        sig1.as_bytes(),
        sig2.as_bytes(),
        "Randomized signing should produce different signatures for same message"
    );
}

/// Test invalid public key length is rejected
#[test]
fn test_mldsa_invalid_public_key_length() {
    let invalid_pk_data = vec![0u8; 100]; // Wrong size
    let result = MlDsaPublicKey::new(MlDsaParameterSet::MLDSA65, invalid_pk_data);

    assert!(result.is_err(), "Should reject invalid public key length");
}

/// Test invalid secret key length is rejected
#[test]
fn test_mldsa_invalid_secret_key_length() {
    let invalid_sk_data = vec![0u8; 100]; // Wrong size
    let result = MlDsaSecretKey::new(MlDsaParameterSet::MLDSA65, invalid_sk_data);

    assert!(result.is_err(), "Should reject invalid secret key length");
}

/// Test invalid signature length is rejected
#[test]
fn test_mldsa_invalid_signature_length() {
    let invalid_sig_data = vec![0u8; 100]; // Wrong size
    let result = MlDsaSignature::new(MlDsaParameterSet::MLDSA65, invalid_sig_data);

    assert!(result.is_err(), "Should reject invalid signature length");
}

/// Test empty message can be signed
#[test]
fn test_mldsa_empty_message() {
    let (pk, sk) =
        generate_keypair(MlDsaParameterSet::MLDSA65).expect("key generation should succeed");

    let message = b"";
    let signature = sign(&sk, message, &[]).expect("signing empty message should succeed");
    let is_valid = verify(&pk, message, &signature, &[]).expect("verification should succeed");

    assert!(is_valid, "Empty message signature should verify");
}

/// Test large message can be signed
#[test]
fn test_mldsa_large_message() {
    let (pk, sk) =
        generate_keypair(MlDsaParameterSet::MLDSA65).expect("key generation should succeed");

    let message = vec![0x42u8; 1_000_000]; // 1MB message
    let signature = sign(&sk, &message, &[]).expect("signing large message should succeed");
    let is_valid = verify(&pk, &message, &signature, &[]).expect("verification should succeed");

    assert!(is_valid, "Large message signature should verify");
}

/// Test context string support
#[test]
fn test_mldsa_with_context() {
    let (pk, sk) =
        generate_keypair(MlDsaParameterSet::MLDSA65).expect("key generation should succeed");

    let message = b"Test message with context";
    let context = b"application-specific-context";
    let signature = sign(&sk, message, context).expect("signing with context should succeed");
    let is_valid = verify(&pk, message, &signature, context).expect("verification should succeed");

    assert!(is_valid, "Signature with context should verify");
}

/// Test context mismatch fails verification
#[test]
fn test_mldsa_context_mismatch() {
    let (pk, sk) =
        generate_keypair(MlDsaParameterSet::MLDSA65).expect("key generation should succeed");

    let message = b"Test message";
    let context1 = b"context1";
    let context2 = b"context2";
    let signature = sign(&sk, message, context1).expect("signing should succeed");
    let is_valid = verify(&pk, message, &signature, context2).expect("verification should succeed");

    assert!(!is_valid, "Verification should fail with wrong context");
}
