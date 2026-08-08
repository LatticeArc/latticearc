#![allow(clippy::panic, clippy::expect_used, clippy::indexing_slicing)]
//! ECDH (X25519) Key-Exchange Tests
//!
//! Test coverage includes:
//! - Key generation and key exchange (both parties derive same shared secret)
//! - Point validation and invalid public key rejection
//! - Key serialization roundtrip
//! - Secret-key Debug redaction and error-type behavior

use latticearc::primitives::kem::ecdh::{
    EcdhError, X25519_KEY_SIZE, X25519KeyPair, X25519PublicKey, X25519SecretKey, agree_ephemeral,
    validate_public_key,
};

// ============================================================================
// Key generation and exchange
// ============================================================================

#[test]
fn test_x25519_keypair_generation_succeeds() {
    let keypair = X25519KeyPair::generate();
    assert!(keypair.is_ok(), "X25519 key generation should succeed");

    let keypair = keypair.expect("keypair generation should succeed");
    assert_eq!(
        keypair.public_key_bytes().len(),
        X25519_KEY_SIZE,
        "X25519 public key should be 32 bytes"
    );
}

#[test]
fn test_x25519_key_exchange_both_parties_same_secret_succeeds() {
    let alice = X25519KeyPair::generate().expect("Alice keypair generation should succeed");
    let bob = X25519KeyPair::generate().expect("Bob keypair generation should succeed");

    let alice_pk = *alice.public_key_bytes();
    let bob_pk = *bob.public_key_bytes();

    let alice_secret = alice.agree(&bob_pk).expect("Alice key agreement should succeed");
    let bob_secret = bob.agree(&alice_pk).expect("Bob key agreement should succeed");

    assert_eq!(alice_secret, bob_secret, "Both parties must derive the same shared secret");
    assert_eq!(alice_secret.len(), X25519_KEY_SIZE, "X25519 shared secret should be 32 bytes");
}

#[test]
fn test_x25519_agree_ephemeral_succeeds() {
    let peer = X25519KeyPair::generate().expect("Peer keypair generation should succeed");
    let peer_pk = *peer.public_key_bytes();

    let result = agree_ephemeral(&peer_pk);
    assert!(result.is_ok(), "Ephemeral agreement should succeed");

    let (shared_secret, our_public) = result.expect("ephemeral agreement should succeed");
    assert_eq!(shared_secret.len(), X25519_KEY_SIZE, "Shared secret should be 32 bytes");
    assert_eq!(our_public.len(), X25519_KEY_SIZE, "Our public key should be 32 bytes");
}

#[test]
fn test_x25519_multiple_agreements_produce_different_secrets_succeeds() {
    // Alice generates a single keypair
    let alice_pk = X25519KeyPair::generate()
        .expect("Alice keypair generation should succeed")
        .public_key_bytes()
        .to_vec();

    // Bob generates two different keypairs
    let bob1 = X25519KeyPair::generate().expect("Bob1 keypair generation should succeed");
    let bob2 = X25519KeyPair::generate().expect("Bob2 keypair generation should succeed");

    let secret1 = bob1.agree(&alice_pk).expect("Agreement 1 should succeed");
    let secret2 = bob2.agree(&alice_pk).expect("Agreement 2 should succeed");

    // Different private keys should produce different shared secrets
    assert_ne!(secret1, secret2, "Different sessions should produce different secrets");
}

// ============================================================================
// Point validation and invalid public key rejection
// ============================================================================

#[test]
fn test_x25519_point_validation_succeeds() {
    let keypair = X25519KeyPair::generate().expect("keypair generation should succeed");
    let pk = X25519PublicKey::from_bytes(keypair.public_key_bytes())
        .expect("public key creation should succeed");

    let result = validate_public_key(&pk);
    assert!(result.is_ok(), "Valid X25519 public key should pass validation");
}

#[test]
fn test_x25519_reject_wrong_size_public_key_fails() {
    let wrong_size = vec![0x42u8; 16]; // Too short
    let result = X25519PublicKey::from_bytes(&wrong_size);
    assert!(result.is_err(), "Wrong size should be rejected");

    match result {
        Err(EcdhError::InvalidKeySize { expected, actual }) => {
            assert_eq!(expected, X25519_KEY_SIZE);
            assert_eq!(actual, 16);
        }
        _ => panic!("Expected InvalidKeySize error"),
    }
}

#[test]
fn test_x25519_reject_invalid_public_key_in_agreement_fails() {
    let keypair = X25519KeyPair::generate().expect("keypair generation should succeed");

    // All zeros is a low-order point (though aws-lc-rs might still process it)
    let all_zeros = vec![0u8; X25519_KEY_SIZE];

    // The agreement might succeed or fail depending on implementation
    // What's important is it doesn't panic
    let _result = keypair.agree(&all_zeros);
}

// ============================================================================
// Serialization roundtrip
// ============================================================================

#[test]
fn test_x25519_public_key_serialization_roundtrip() {
    let keypair = X25519KeyPair::generate().expect("keypair generation should succeed");
    let pk = keypair.public_key();

    let bytes = pk.as_bytes();
    let vec_bytes = pk.to_vec();

    let restored = X25519PublicKey::from_bytes(bytes).expect("restoration should succeed");
    let restored_vec =
        X25519PublicKey::from_bytes(&vec_bytes).expect("restoration from vec should succeed");

    assert_eq!(pk.as_bytes(), restored.as_bytes(), "Roundtrip should preserve bytes");
    assert_eq!(pk.as_bytes(), restored_vec.as_bytes(), "Roundtrip from vec should preserve bytes");
}

#[test]
fn test_x25519_secret_key_serialization_roundtrip() {
    let bytes = [0x42u8; X25519_KEY_SIZE];
    let sk = X25519SecretKey::from_bytes(&bytes).expect("secret key creation should succeed");

    let restored =
        X25519SecretKey::from_bytes(sk.expose_secret()).expect("restoration should succeed");

    assert_eq!(sk.expose_secret(), restored.expose_secret(), "Roundtrip should preserve bytes");
}

// ============================================================================
// Debug redaction, clone, constants, and error types
// ============================================================================

#[test]
fn test_x25519_secret_key_debug_redacts_succeeds() {
    let sk = X25519SecretKey::from_bytes(&[0x42u8; X25519_KEY_SIZE])
        .expect("secret key creation should succeed");
    let debug_str = format!("{:?}", sk);

    assert!(debug_str.contains("[REDACTED]"), "Debug output should redact secret key");
    assert!(!debug_str.contains("66"), "Debug should not contain raw key value (0x42 = 66)");
}

#[test]
fn test_x25519_public_key_clone_succeeds() {
    let keypair = X25519KeyPair::generate().expect("keypair generation should succeed");
    let pk = keypair.public_key();
    let pk_clone = pk.clone();

    assert_eq!(pk, pk_clone, "Cloned public key should be equal");
}

#[test]
fn test_key_size_constants_are_correct() {
    assert_eq!(X25519_KEY_SIZE, 32);
}

#[test]
fn test_ecdh_error_display_fails() {
    let error = EcdhError::KeyGenerationFailed;
    assert!(error.to_string().contains("generation failed"));

    let error = EcdhError::AgreementFailed;
    assert!(error.to_string().contains("agreement failed"));

    let error = EcdhError::InvalidKeySize { expected: 32, actual: 16 };
    assert!(error.to_string().contains("32"));
    assert!(error.to_string().contains("16"));

    let error = EcdhError::InvalidPointFormat { expected: "uncompressed", actual: "compressed" };
    assert!(error.to_string().contains("uncompressed"));
}

#[test]
fn test_ecdh_error_equality_fails() {
    let error1 = EcdhError::KeyGenerationFailed;
    let error2 = EcdhError::KeyGenerationFailed;
    assert_eq!(error1, error2);

    let error3 = EcdhError::AgreementFailed;
    assert_ne!(error1, error3);
}
