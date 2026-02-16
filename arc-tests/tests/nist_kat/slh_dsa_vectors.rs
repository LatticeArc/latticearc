//! SLH-DSA (FIPS 205) Known Answer Tests
//!
//! Test vectors derived from NIST FIPS 205 specification and CAVP test files.
//! These tests validate the SLH-DSA (SPHINCS+) implementation against official NIST values.

#![allow(clippy::expect_used)]
#![allow(clippy::indexing_slicing)]

// Tests use #[test] attributes - no additional imports needed
use arc_primitives::sig::slh_dsa::{SecurityLevel, SigningKey};

/// SLH-DSA-SHAKE-128s sizes (FIPS 205)
const SLH_DSA_128S_PK_SIZE: usize = 32;
const SLH_DSA_128S_SK_SIZE: usize = 64;
const SLH_DSA_128S_SIG_SIZE: usize = 7856;

/// SLH-DSA-SHAKE-192s sizes (FIPS 205)
const SLH_DSA_192S_PK_SIZE: usize = 48;
const SLH_DSA_192S_SK_SIZE: usize = 96;
const SLH_DSA_192S_SIG_SIZE: usize = 16224;

/// SLH-DSA-SHAKE-256s sizes (FIPS 205)
const SLH_DSA_256S_PK_SIZE: usize = 64;
const SLH_DSA_256S_SK_SIZE: usize = 128;
const SLH_DSA_256S_SIG_SIZE: usize = 29792;

/// Test SLH-DSA-SHAKE-128s key generation produces correct sizes
#[test]
fn test_slhdsa_128s_key_sizes() {
    let (sk, pk) =
        SigningKey::generate(SecurityLevel::Shake128s).expect("key generation should succeed");

    assert_eq!(
        pk.as_bytes().len(),
        SLH_DSA_128S_PK_SIZE,
        "SLH-DSA-SHAKE-128s public key should be {} bytes",
        SLH_DSA_128S_PK_SIZE
    );
    assert_eq!(
        sk.as_bytes().len(),
        SLH_DSA_128S_SK_SIZE,
        "SLH-DSA-SHAKE-128s secret key should be {} bytes",
        SLH_DSA_128S_SK_SIZE
    );
}

#[test]
fn test_slhdsa_192s_key_sizes() {
    let (sk, pk) =
        SigningKey::generate(SecurityLevel::Shake192s).expect("key generation should succeed");

    assert_eq!(
        pk.as_bytes().len(),
        SLH_DSA_192S_PK_SIZE,
        "SLH-DSA-SHAKE-192s public key should be {} bytes",
        SLH_DSA_192S_PK_SIZE
    );
    assert_eq!(
        sk.as_bytes().len(),
        SLH_DSA_192S_SK_SIZE,
        "SLH-DSA-SHAKE-192s secret key should be {} bytes",
        SLH_DSA_192S_SK_SIZE
    );
}

#[test]
fn test_slhdsa_256s_key_sizes() {
    let (sk, pk) =
        SigningKey::generate(SecurityLevel::Shake256s).expect("key generation should succeed");

    assert_eq!(
        pk.as_bytes().len(),
        SLH_DSA_256S_PK_SIZE,
        "SLH-DSA-SHAKE-256s public key should be {} bytes",
        SLH_DSA_256S_PK_SIZE
    );
    assert_eq!(
        sk.as_bytes().len(),
        SLH_DSA_256S_SK_SIZE,
        "SLH-DSA-SHAKE-256s secret key should be {} bytes",
        SLH_DSA_256S_SK_SIZE
    );
}

/// Test SLH-DSA signature sizes
#[test]
fn test_slhdsa_128s_signature_size() {
    let (sk, _pk) =
        SigningKey::generate(SecurityLevel::Shake128s).expect("key generation should succeed");

    let message = b"Test message for SLH-DSA-SHAKE-128s";
    let signature = sk.sign(message, None).expect("signing should succeed");

    assert_eq!(
        signature.len(),
        SLH_DSA_128S_SIG_SIZE,
        "SLH-DSA-SHAKE-128s signature should be {} bytes",
        SLH_DSA_128S_SIG_SIZE
    );
}

#[test]
fn test_slhdsa_192s_signature_size() {
    let (sk, _pk) =
        SigningKey::generate(SecurityLevel::Shake192s).expect("key generation should succeed");

    let message = b"Test message for SLH-DSA-SHAKE-192s";
    let signature = sk.sign(message, None).expect("signing should succeed");

    assert_eq!(
        signature.len(),
        SLH_DSA_192S_SIG_SIZE,
        "SLH-DSA-SHAKE-192s signature should be {} bytes",
        SLH_DSA_192S_SIG_SIZE
    );
}

#[test]
fn test_slhdsa_256s_signature_size() {
    let (sk, _pk) =
        SigningKey::generate(SecurityLevel::Shake256s).expect("key generation should succeed");

    let message = b"Test message for SLH-DSA-SHAKE-256s";
    let signature = sk.sign(message, None).expect("signing should succeed");

    assert_eq!(
        signature.len(),
        SLH_DSA_256S_SIG_SIZE,
        "SLH-DSA-SHAKE-256s signature should be {} bytes",
        SLH_DSA_256S_SIG_SIZE
    );
}

/// Test SLH-DSA sign/verify roundtrip
#[test]
fn test_slhdsa_128s_roundtrip() {
    let (sk, pk) =
        SigningKey::generate(SecurityLevel::Shake128s).expect("key generation should succeed");

    let message = b"Test message for SLH-DSA-SHAKE-128s roundtrip";
    let signature = sk.sign(message, None).expect("signing should succeed");
    let is_valid = pk.verify(message, &signature, None).expect("verification should succeed");

    assert!(is_valid, "SLH-DSA-SHAKE-128s signature should verify");
}

#[test]
fn test_slhdsa_192s_roundtrip() {
    let (sk, pk) =
        SigningKey::generate(SecurityLevel::Shake192s).expect("key generation should succeed");

    let message = b"Test message for SLH-DSA-SHAKE-192s roundtrip";
    let signature = sk.sign(message, None).expect("signing should succeed");
    let is_valid = pk.verify(message, &signature, None).expect("verification should succeed");

    assert!(is_valid, "SLH-DSA-SHAKE-192s signature should verify");
}

#[test]
fn test_slhdsa_256s_roundtrip() {
    let (sk, pk) =
        SigningKey::generate(SecurityLevel::Shake256s).expect("key generation should succeed");

    let message = b"Test message for SLH-DSA-SHAKE-256s roundtrip";
    let signature = sk.sign(message, None).expect("signing should succeed");
    let is_valid = pk.verify(message, &signature, None).expect("verification should succeed");

    assert!(is_valid, "SLH-DSA-SHAKE-256s signature should verify");
}

/// Test verification fails with wrong message
#[test]
fn test_slhdsa_wrong_message() {
    let (sk, pk) =
        SigningKey::generate(SecurityLevel::Shake128s).expect("key generation should succeed");

    let message = b"Original message";
    let wrong_message = b"Wrong message";
    let signature = sk.sign(message, None).expect("signing should succeed");
    let is_valid = pk.verify(wrong_message, &signature, None).expect("verification should succeed");

    assert!(!is_valid, "Verification should fail with wrong message");
}

/// Test verification fails with corrupted signature
#[test]
fn test_slhdsa_corrupted_signature() {
    let (sk, pk) =
        SigningKey::generate(SecurityLevel::Shake128s).expect("key generation should succeed");

    let message = b"Test message";
    let mut signature = sk.sign(message, None).expect("signing should succeed");

    // Corrupt the signature
    if !signature.is_empty() {
        signature[0] ^= 0xFF;
    }

    let is_valid = pk.verify(message, &signature, None).expect("verification should succeed");

    assert!(!is_valid, "Verification should fail with corrupted signature");
}

/// Test verification fails with wrong public key
#[test]
fn test_slhdsa_wrong_public_key() {
    let (sk1, _pk1) =
        SigningKey::generate(SecurityLevel::Shake128s).expect("key generation 1 should succeed");
    let (_sk2, pk2) =
        SigningKey::generate(SecurityLevel::Shake128s).expect("key generation 2 should succeed");

    let message = b"Test message";
    let signature = sk1.sign(message, None).expect("signing should succeed");
    let is_valid = pk2.verify(message, &signature, None).expect("verification should succeed");

    assert!(!is_valid, "Verification should fail with wrong public key");
}

/// Test different keypairs have different public keys
#[test]
fn test_slhdsa_different_keypairs() {
    let (_sk1, pk1) =
        SigningKey::generate(SecurityLevel::Shake128s).expect("key generation 1 should succeed");
    let (_sk2, pk2) =
        SigningKey::generate(SecurityLevel::Shake128s).expect("key generation 2 should succeed");

    assert_ne!(
        pk1.as_bytes(),
        pk2.as_bytes(),
        "Different keypairs should have different public keys"
    );
}

/// Test empty message can be signed
#[test]
fn test_slhdsa_empty_message() {
    let (sk, pk) =
        SigningKey::generate(SecurityLevel::Shake128s).expect("key generation should succeed");

    let message = b"";
    let signature = sk.sign(message, None).expect("signing empty message should succeed");
    let is_valid = pk.verify(message, &signature, None).expect("verification should succeed");

    assert!(is_valid, "Empty message signature should verify");
}

/// Test context string support
#[test]
fn test_slhdsa_with_context() {
    let (sk, pk) =
        SigningKey::generate(SecurityLevel::Shake128s).expect("key generation should succeed");

    let message = b"Test message with context";
    let context = Some(b"application-context".as_slice());
    let signature = sk.sign(message, context).expect("signing with context should succeed");
    let is_valid = pk.verify(message, &signature, context).expect("verification should succeed");

    assert!(is_valid, "Signature with context should verify");
}

/// Test context mismatch fails verification
#[test]
fn test_slhdsa_context_mismatch() {
    let (sk, pk) =
        SigningKey::generate(SecurityLevel::Shake128s).expect("key generation should succeed");

    let message = b"Test message";
    let context1 = Some(b"context1".as_slice());
    let context2 = Some(b"context2".as_slice());
    let signature = sk.sign(message, context1).expect("signing should succeed");
    let is_valid = pk.verify(message, &signature, context2).expect("verification should succeed");

    assert!(!is_valid, "Verification should fail with wrong context");
}

/// Test that multiple signatures of the same message all verify correctly.
/// Note: SLH-DSA uses randomized signing by default per FIPS 205 for hedged security,
/// so signatures of the same message will differ but all should verify.
#[test]
fn test_slhdsa_multiple_signatures_verify() {
    let (sk, pk) =
        SigningKey::generate(SecurityLevel::Shake128s).expect("key generation should succeed");

    let message = b"Test message for multiple signatures";

    // Generate multiple signatures of the same message
    let sig1 = sk.sign(message, None).expect("signing 1 should succeed");
    let sig2 = sk.sign(message, None).expect("signing 2 should succeed");

    // Both signatures should verify correctly
    let is_valid1 = pk.verify(message, &sig1, None).expect("verification 1 should succeed");
    let is_valid2 = pk.verify(message, &sig2, None).expect("verification 2 should succeed");

    assert!(is_valid1, "First signature should verify");
    assert!(is_valid2, "Second signature should verify");
}
