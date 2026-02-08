#![allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic_in_result_fn,
    clippy::unnecessary_wraps,
    clippy::redundant_clone,
    clippy::useless_vec,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::clone_on_copy,
    clippy::len_zero,
    clippy::single_match,
    clippy::unnested_or_patterns,
    clippy::default_constructed_unit_structs,
    clippy::redundant_closure_for_method_calls,
    clippy::semicolon_if_nothing_returned,
    clippy::unnecessary_unwrap,
    clippy::redundant_pattern_matching,
    clippy::missing_const_for_thread_local,
    clippy::get_first,
    clippy::float_cmp,
    clippy::needless_borrows_for_generic_args,
    unused_qualifications
)]

//! Integration tests for the unified signing API:
//! `generate_signing_keypair()` + `sign_with_key()` + `verify()`

use arc_core::{CryptoConfig, SecurityLevel, generate_signing_keypair, sign_with_key, verify};

// ============================================================================
// Hybrid roundtrip (default config)
// ============================================================================

#[test]
fn test_hybrid_default_roundtrip() {
    let config = CryptoConfig::new();
    let (pk, sk, scheme) = generate_signing_keypair(config.clone()).unwrap();

    assert!(
        scheme.contains("hybrid") || scheme.contains("ml-dsa"),
        "Default scheme should be hybrid or ML-DSA, got: {}",
        scheme
    );

    let message = b"Hello, unified signing API!";
    let signed = sign_with_key(message, &sk, &pk, config).unwrap();

    assert_eq!(signed.data, message);
    assert_eq!(signed.scheme, scheme);

    let valid = verify(&signed, CryptoConfig::new()).unwrap();
    assert!(valid, "Signature should verify with matching public key");
}

// ============================================================================
// Persistent identity: same keypair, multiple messages
// ============================================================================

#[test]
fn test_persistent_identity() {
    let config = CryptoConfig::new();
    let (pk, sk, _scheme) = generate_signing_keypair(config.clone()).unwrap();

    for i in 0..10 {
        let message = format!("Message number {}", i);
        let signed = sign_with_key(message.as_bytes(), &sk, &pk, config.clone()).unwrap();

        let valid = verify(&signed, CryptoConfig::new()).unwrap();
        assert!(valid, "Message {} should verify", i);

        // Public key in SignedData matches our stored key
        assert_eq!(signed.metadata.public_key, pk);
    }
}

// ============================================================================
// PQ-only roundtrip (Quantum security level → ML-DSA-87 only)
// ============================================================================

#[test]
fn test_pq_only_ml_dsa_87() {
    let config = CryptoConfig::new().security_level(SecurityLevel::Maximum);
    let (pk, sk, scheme) = generate_signing_keypair(config.clone()).unwrap();

    assert!(
        scheme.contains("ml-dsa-87"),
        "Maximum security should select ML-DSA-87, got: {}",
        scheme
    );

    let message = b"PQ-only signing test";
    let signed = sign_with_key(message, &sk, &pk, config).unwrap();

    let valid = verify(&signed, CryptoConfig::new()).unwrap();
    assert!(valid);
}

// ============================================================================
// ML-DSA-44 (Standard security)
// ============================================================================

#[test]
fn test_ml_dsa_44_standard() {
    let config = CryptoConfig::new().security_level(SecurityLevel::Standard);
    let (pk, sk, scheme) = generate_signing_keypair(config.clone()).unwrap();

    assert!(
        scheme.contains("ml-dsa-44") || scheme.contains("ed25519"),
        "Standard security should select ML-DSA-44 or Ed25519, got: {}",
        scheme
    );

    let message = b"Standard security test";
    let signed = sign_with_key(message, &sk, &pk, config).unwrap();

    let valid = verify(&signed, CryptoConfig::new()).unwrap();
    assert!(valid);
}

// ============================================================================
// Cross-key rejection: sign with A, verify fails with B's public key
// ============================================================================

#[test]
fn test_cross_key_rejection() {
    let config = CryptoConfig::new();
    let (pk_a, sk_a, _) = generate_signing_keypair(config.clone()).unwrap();
    let (pk_b, _sk_b, _) = generate_signing_keypair(config.clone()).unwrap();

    // Ensure different keys
    assert_ne!(pk_a, pk_b, "Two generated keypairs must have different public keys");

    let message = b"Signed by key A";
    let signed_a = sign_with_key(message, &sk_a, &pk_a, config).unwrap();

    // Replace public key with B's
    let mut tampered = signed_a.clone();
    tampered.metadata.public_key = pk_b;

    match verify(&tampered, CryptoConfig::new()) {
        Ok(valid) => assert!(!valid, "Cross-key verification should fail"),
        Err(_) => {} // Error is also acceptable
    }
}

// ============================================================================
// Tampered message rejection
// ============================================================================

#[test]
fn test_tampered_message_rejection() {
    let config = CryptoConfig::new();
    let (pk, sk, _) = generate_signing_keypair(config.clone()).unwrap();

    let message = b"Original message";
    let signed = sign_with_key(message, &sk, &pk, config).unwrap();

    // Tamper with message
    let mut tampered = signed.clone();
    tampered.data = b"Modified message".to_vec();

    match verify(&tampered, CryptoConfig::new()) {
        Ok(valid) => assert!(!valid, "Tampered message should fail verification"),
        Err(_) => {} // Error is also acceptable
    }
}

// ============================================================================
// Tampered signature rejection
// ============================================================================

#[test]
fn test_tampered_signature_rejection() {
    let config = CryptoConfig::new();
    let (pk, sk, _) = generate_signing_keypair(config.clone()).unwrap();

    let message = b"Sign me";
    let signed = sign_with_key(message, &sk, &pk, config).unwrap();

    // Flip first byte of signature
    let mut tampered = signed.clone();
    if let Some(byte) = tampered.metadata.signature.first_mut() {
        *byte ^= 0xFF;
    }

    match verify(&tampered, CryptoConfig::new()) {
        Ok(valid) => assert!(!valid, "Tampered signature should fail verification"),
        Err(_) => {} // Error is also acceptable
    }
}

// ============================================================================
// Scheme consistency: keygen and sign select the same scheme
// ============================================================================

#[test]
fn test_scheme_consistency() {
    let levels = [SecurityLevel::Standard, SecurityLevel::High, SecurityLevel::Maximum];

    for level in &levels {
        let config = CryptoConfig::new().security_level(level.clone());
        let (pk, sk, keygen_scheme) = generate_signing_keypair(config.clone()).unwrap();

        let message = b"Scheme consistency test";
        let signed = sign_with_key(message, &sk, &pk, config).unwrap();

        assert_eq!(
            signed.scheme, keygen_scheme,
            "sign_with_key scheme ({}) should match generate_signing_keypair scheme ({}) for {:?}",
            signed.scheme, keygen_scheme, level
        );
    }
}

// ============================================================================
// Empty message
// ============================================================================

#[test]
fn test_empty_message() {
    let config = CryptoConfig::new();
    let (pk, sk, _) = generate_signing_keypair(config.clone()).unwrap();

    let message = b"";
    let signed = sign_with_key(message, &sk, &pk, config).unwrap();

    let valid = verify(&signed, CryptoConfig::new()).unwrap();
    assert!(valid, "Empty message signature should verify");
}

// ============================================================================
// Large message
// ============================================================================

#[test]
fn test_large_message() {
    let config = CryptoConfig::new();
    let (pk, sk, _) = generate_signing_keypair(config.clone()).unwrap();

    let message = vec![0xABu8; 10_000];
    let signed = sign_with_key(&message, &sk, &pk, config).unwrap();

    let valid = verify(&signed, CryptoConfig::new()).unwrap();
    assert!(valid, "Large message signature should verify");
}

// ============================================================================
// SLH-DSA roundtrip (if Quantum level selects it)
// ============================================================================

#[test]
fn test_slh_dsa_128s_roundtrip() {
    // Use Quantum security level which selects PQ-only
    let config = CryptoConfig::new().security_level(SecurityLevel::Quantum);
    let (pk, sk, scheme) = generate_signing_keypair(config.clone()).unwrap();

    // Quantum level should pick a PQ-only scheme
    let message = b"SLH-DSA test message";
    let signed = sign_with_key(message, &sk, &pk, config).unwrap();

    let valid = verify(&signed, CryptoConfig::new()).unwrap();
    assert!(valid, "SLH-DSA/ML-DSA roundtrip should verify, scheme: {}", scheme);
}
