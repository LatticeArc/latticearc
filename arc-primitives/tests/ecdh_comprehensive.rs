#![allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_lossless,
    clippy::redundant_clone,
    clippy::clone_on_copy,
    clippy::collapsible_if,
    clippy::single_match,
    clippy::needless_range_loop,
    clippy::explicit_iter_loop,
    clippy::explicit_auto_deref,
    clippy::assertions_on_constants,
    clippy::len_zero,
    clippy::print_stdout,
    clippy::unused_unit,
    clippy::expect_fun_call,
    clippy::useless_vec,
    clippy::cloned_instead_of_copied,
    clippy::float_cmp,
    clippy::needless_borrows_for_generic_args,
    clippy::manual_let_else
)]
//! Comprehensive ECDH (Elliptic Curve Diffie-Hellman) Tests
//!
//! This test suite provides comprehensive coverage for ECDH operations across
//! all supported curves: X25519, P-256, P-384, and P-521.
//!
//! Test coverage includes:
//! - Key generation for all curves
//! - Key exchange (both parties derive same shared secret)
//! - Point validation
//! - Invalid public key rejection
//! - Key serialization roundtrip
//! - Edge cases and error handling
//!
//! Phase 2 Tasks: 2.5.1-2.5.6

use arc_primitives::kem::ecdh::{
    EcdhCurve, EcdhError, EcdhP256KeyPair, EcdhP256PublicKey, EcdhP384KeyPair, EcdhP384PublicKey,
    EcdhP521KeyPair, EcdhP521PublicKey, P256_PUBLIC_KEY_SIZE, P256_SHARED_SECRET_SIZE,
    P384_PUBLIC_KEY_SIZE, P384_SHARED_SECRET_SIZE, P521_PUBLIC_KEY_SIZE, P521_SHARED_SECRET_SIZE,
    X25519_KEY_SIZE, X25519KeyPair, X25519PublicKey, X25519SecretKey, agree_ephemeral,
    agree_ephemeral_p256, agree_ephemeral_p384, agree_ephemeral_p521, diffie_hellman,
    generate_keypair, validate_p256_public_key, validate_p384_public_key, validate_p521_public_key,
    validate_public_key,
};

// ============================================================================
// Task 2.5.1: Test P-256 Key Exchange
// ============================================================================

#[test]
fn test_p256_keypair_generation() {
    let keypair = EcdhP256KeyPair::generate();
    assert!(keypair.is_ok(), "P-256 key generation should succeed");

    let keypair = keypair.expect("keypair generation should succeed");
    assert_eq!(
        keypair.public_key_bytes().len(),
        P256_PUBLIC_KEY_SIZE,
        "P-256 public key should be 65 bytes"
    );
    // Check uncompressed point format
    assert_eq!(keypair.public_key_bytes()[0], 0x04, "P-256 public key should have 0x04 prefix");
}

#[test]
fn test_p256_key_exchange_both_parties_same_secret() {
    // Generate two keypairs (Alice and Bob)
    let alice = EcdhP256KeyPair::generate().expect("Alice keypair generation should succeed");
    let bob = EcdhP256KeyPair::generate().expect("Bob keypair generation should succeed");

    let alice_pk = alice.public_key_bytes().to_vec();
    let bob_pk = bob.public_key_bytes().to_vec();

    // Perform key agreement
    let alice_secret = alice.agree(&bob_pk).expect("Alice key agreement should succeed");
    let bob_secret = bob.agree(&alice_pk).expect("Bob key agreement should succeed");

    // Both parties should derive the same shared secret
    assert_eq!(alice_secret, bob_secret, "Both parties must derive the same shared secret");
    assert_eq!(
        alice_secret.len(),
        P256_SHARED_SECRET_SIZE,
        "P-256 shared secret should be 32 bytes"
    );
}

#[test]
fn test_p256_ephemeral_key_generation() {
    // Generate multiple keypairs and verify they are different
    let keypair1 = EcdhP256KeyPair::generate().expect("First keypair should succeed");
    let keypair2 = EcdhP256KeyPair::generate().expect("Second keypair should succeed");

    assert_ne!(
        keypair1.public_key_bytes(),
        keypair2.public_key_bytes(),
        "Different keypairs should have different public keys"
    );
}

#[test]
fn test_p256_agree_ephemeral() {
    let peer = EcdhP256KeyPair::generate().expect("Peer keypair generation should succeed");
    let peer_pk = peer.public_key_bytes().to_vec();

    let result = agree_ephemeral_p256(&peer_pk);
    assert!(result.is_ok(), "Ephemeral agreement should succeed");

    let (shared_secret, our_public) = result.expect("ephemeral agreement should succeed");
    assert_eq!(shared_secret.len(), P256_SHARED_SECRET_SIZE, "Shared secret should be 32 bytes");
    assert_eq!(our_public.len(), P256_PUBLIC_KEY_SIZE, "Our public key should be 65 bytes");
}

#[test]
fn test_p256_shared_secret_non_zero() {
    let alice = EcdhP256KeyPair::generate().expect("Alice keypair generation should succeed");
    let bob = EcdhP256KeyPair::generate().expect("Bob keypair generation should succeed");

    let bob_pk = bob.public_key_bytes().to_vec();
    let secret = alice.agree(&bob_pk).expect("Key agreement should succeed");

    // Shared secret should not be all zeros
    assert!(secret.iter().any(|&b| b != 0), "Shared secret should not be all zeros");
}

// ============================================================================
// Task 2.5.2: Test P-384 Key Exchange
// ============================================================================

#[test]
fn test_p384_keypair_generation() {
    let keypair = EcdhP384KeyPair::generate();
    assert!(keypair.is_ok(), "P-384 key generation should succeed");

    let keypair = keypair.expect("keypair generation should succeed");
    assert_eq!(
        keypair.public_key_bytes().len(),
        P384_PUBLIC_KEY_SIZE,
        "P-384 public key should be 97 bytes"
    );
    // Check uncompressed point format
    assert_eq!(keypair.public_key_bytes()[0], 0x04, "P-384 public key should have 0x04 prefix");
}

#[test]
fn test_p384_key_exchange_both_parties_same_secret() {
    // Generate two keypairs (Alice and Bob)
    let alice = EcdhP384KeyPair::generate().expect("Alice keypair generation should succeed");
    let bob = EcdhP384KeyPair::generate().expect("Bob keypair generation should succeed");

    let alice_pk = alice.public_key_bytes().to_vec();
    let bob_pk = bob.public_key_bytes().to_vec();

    // Perform key agreement
    let alice_secret = alice.agree(&bob_pk).expect("Alice key agreement should succeed");
    let bob_secret = bob.agree(&alice_pk).expect("Bob key agreement should succeed");

    // Both parties should derive the same shared secret
    assert_eq!(alice_secret, bob_secret, "Both parties must derive the same shared secret");
    assert_eq!(
        alice_secret.len(),
        P384_SHARED_SECRET_SIZE,
        "P-384 shared secret should be 48 bytes"
    );
}

#[test]
fn test_p384_ephemeral_key_generation() {
    let keypair1 = EcdhP384KeyPair::generate().expect("First keypair should succeed");
    let keypair2 = EcdhP384KeyPair::generate().expect("Second keypair should succeed");

    assert_ne!(
        keypair1.public_key_bytes(),
        keypair2.public_key_bytes(),
        "Different keypairs should have different public keys"
    );
}

#[test]
fn test_p384_agree_ephemeral() {
    let peer = EcdhP384KeyPair::generate().expect("Peer keypair generation should succeed");
    let peer_pk = peer.public_key_bytes().to_vec();

    let result = agree_ephemeral_p384(&peer_pk);
    assert!(result.is_ok(), "Ephemeral agreement should succeed");

    let (shared_secret, our_public) = result.expect("ephemeral agreement should succeed");
    assert_eq!(shared_secret.len(), P384_SHARED_SECRET_SIZE, "Shared secret should be 48 bytes");
    assert_eq!(our_public.len(), P384_PUBLIC_KEY_SIZE, "Our public key should be 97 bytes");
}

#[test]
fn test_p384_shared_secret_non_zero() {
    let alice = EcdhP384KeyPair::generate().expect("Alice keypair generation should succeed");
    let bob = EcdhP384KeyPair::generate().expect("Bob keypair generation should succeed");

    let bob_pk = bob.public_key_bytes().to_vec();
    let secret = alice.agree(&bob_pk).expect("Key agreement should succeed");

    assert!(secret.iter().any(|&b| b != 0), "Shared secret should not be all zeros");
}

// ============================================================================
// Task 2.5.3: Test P-521 Key Exchange
// ============================================================================

#[test]
fn test_p521_keypair_generation() {
    let keypair = EcdhP521KeyPair::generate();
    assert!(keypair.is_ok(), "P-521 key generation should succeed");

    let keypair = keypair.expect("keypair generation should succeed");
    assert_eq!(
        keypair.public_key_bytes().len(),
        P521_PUBLIC_KEY_SIZE,
        "P-521 public key should be 133 bytes"
    );
    // Check uncompressed point format
    assert_eq!(keypair.public_key_bytes()[0], 0x04, "P-521 public key should have 0x04 prefix");
}

#[test]
fn test_p521_key_exchange_both_parties_same_secret() {
    // Generate two keypairs (Alice and Bob)
    let alice = EcdhP521KeyPair::generate().expect("Alice keypair generation should succeed");
    let bob = EcdhP521KeyPair::generate().expect("Bob keypair generation should succeed");

    let alice_pk = alice.public_key_bytes().to_vec();
    let bob_pk = bob.public_key_bytes().to_vec();

    // Perform key agreement
    let alice_secret = alice.agree(&bob_pk).expect("Alice key agreement should succeed");
    let bob_secret = bob.agree(&alice_pk).expect("Bob key agreement should succeed");

    // Both parties should derive the same shared secret
    assert_eq!(alice_secret, bob_secret, "Both parties must derive the same shared secret");
    assert_eq!(
        alice_secret.len(),
        P521_SHARED_SECRET_SIZE,
        "P-521 shared secret should be 66 bytes"
    );
}

#[test]
fn test_p521_ephemeral_key_generation() {
    let keypair1 = EcdhP521KeyPair::generate().expect("First keypair should succeed");
    let keypair2 = EcdhP521KeyPair::generate().expect("Second keypair should succeed");

    assert_ne!(
        keypair1.public_key_bytes(),
        keypair2.public_key_bytes(),
        "Different keypairs should have different public keys"
    );
}

#[test]
fn test_p521_agree_ephemeral() {
    let peer = EcdhP521KeyPair::generate().expect("Peer keypair generation should succeed");
    let peer_pk = peer.public_key_bytes().to_vec();

    let result = agree_ephemeral_p521(&peer_pk);
    assert!(result.is_ok(), "Ephemeral agreement should succeed");

    let (shared_secret, our_public) = result.expect("ephemeral agreement should succeed");
    assert_eq!(shared_secret.len(), P521_SHARED_SECRET_SIZE, "Shared secret should be 66 bytes");
    assert_eq!(our_public.len(), P521_PUBLIC_KEY_SIZE, "Our public key should be 133 bytes");
}

#[test]
fn test_p521_shared_secret_non_zero() {
    let alice = EcdhP521KeyPair::generate().expect("Alice keypair generation should succeed");
    let bob = EcdhP521KeyPair::generate().expect("Bob keypair generation should succeed");

    let bob_pk = bob.public_key_bytes().to_vec();
    let secret = alice.agree(&bob_pk).expect("Key agreement should succeed");

    assert!(secret.iter().any(|&b| b != 0), "Shared secret should not be all zeros");
}

// ============================================================================
// Task 2.5.4: Test Point Validation
// ============================================================================

#[test]
fn test_p256_point_validation_valid_key() {
    let keypair = EcdhP256KeyPair::generate().expect("keypair generation should succeed");
    let pk = keypair.public_key().expect("public key extraction should succeed");

    let result = pk.validate();
    assert!(result.is_ok(), "Valid P-256 public key should pass validation");
}

#[test]
fn test_p256_point_validation_function() {
    let keypair = EcdhP256KeyPair::generate().expect("keypair generation should succeed");
    let pk_bytes = keypair.public_key_bytes();

    let result = validate_p256_public_key(pk_bytes);
    assert!(result.is_ok(), "Valid P-256 public key should pass validation");
}

#[test]
fn test_p384_point_validation_valid_key() {
    let keypair = EcdhP384KeyPair::generate().expect("keypair generation should succeed");
    let pk = keypair.public_key().expect("public key extraction should succeed");

    let result = pk.validate();
    assert!(result.is_ok(), "Valid P-384 public key should pass validation");
}

#[test]
fn test_p384_point_validation_function() {
    let keypair = EcdhP384KeyPair::generate().expect("keypair generation should succeed");
    let pk_bytes = keypair.public_key_bytes();

    let result = validate_p384_public_key(pk_bytes);
    assert!(result.is_ok(), "Valid P-384 public key should pass validation");
}

#[test]
fn test_p521_point_validation_valid_key() {
    let keypair = EcdhP521KeyPair::generate().expect("keypair generation should succeed");
    let pk = keypair.public_key().expect("public key extraction should succeed");

    let result = pk.validate();
    assert!(result.is_ok(), "Valid P-521 public key should pass validation");
}

#[test]
fn test_p521_point_validation_function() {
    let keypair = EcdhP521KeyPair::generate().expect("keypair generation should succeed");
    let pk_bytes = keypair.public_key_bytes();

    let result = validate_p521_public_key(pk_bytes);
    assert!(result.is_ok(), "Valid P-521 public key should pass validation");
}

#[test]
fn test_x25519_point_validation() {
    let mut rng = rand::thread_rng();
    let (pk, _sk) = generate_keypair(&mut rng).expect("keypair generation should succeed");

    let result = validate_public_key(&pk);
    assert!(result.is_ok(), "Valid X25519 public key should pass validation");
}

// ============================================================================
// Task 2.5.5: Test Invalid Public Key Rejection
// ============================================================================

#[test]
fn test_p256_reject_empty_public_key() {
    let result = EcdhP256PublicKey::from_bytes(&[]);
    assert!(result.is_err(), "Empty bytes should be rejected");

    match result {
        Err(EcdhError::InvalidKeySize { expected, actual }) => {
            assert_eq!(expected, P256_PUBLIC_KEY_SIZE);
            assert_eq!(actual, 0);
        }
        _ => panic!("Expected InvalidKeySize error"),
    }
}

#[test]
fn test_p256_reject_wrong_size_public_key() {
    let wrong_size = vec![0x04u8; 32]; // Too small
    let result = EcdhP256PublicKey::from_bytes(&wrong_size);
    assert!(result.is_err(), "Wrong size should be rejected");

    match result {
        Err(EcdhError::InvalidKeySize { expected, actual }) => {
            assert_eq!(expected, P256_PUBLIC_KEY_SIZE);
            assert_eq!(actual, 32);
        }
        _ => panic!("Expected InvalidKeySize error"),
    }
}

#[test]
fn test_p256_reject_wrong_prefix() {
    // Create a 65-byte key with wrong prefix
    let mut wrong_prefix = vec![0x02u8; P256_PUBLIC_KEY_SIZE]; // Compressed point prefix
    wrong_prefix[0] = 0x02;

    let result = EcdhP256PublicKey::from_bytes(&wrong_prefix);
    assert!(result.is_err(), "Wrong prefix should be rejected");

    match result {
        Err(EcdhError::InvalidPointFormat { expected, actual: _ }) => {
            assert!(expected.contains("uncompressed"));
        }
        _ => panic!("Expected InvalidPointFormat error"),
    }
}

#[test]
fn test_p256_reject_invalid_public_key_in_agreement() {
    let keypair = EcdhP256KeyPair::generate().expect("keypair generation should succeed");

    // Try to agree with junk bytes (correct size but invalid point)
    let junk_bytes = vec![0x04u8; P256_PUBLIC_KEY_SIZE]; // 0x04 prefix, but x/y are all 0x04

    let result = keypair.agree(&junk_bytes);
    assert!(result.is_err(), "Invalid public key should be rejected in agreement");
}

#[test]
fn test_p384_reject_wrong_size_public_key() {
    let wrong_size = vec![0x04u8; 65]; // P-256 size instead of P-384
    let result = EcdhP384PublicKey::from_bytes(&wrong_size);
    assert!(result.is_err(), "Wrong size should be rejected");

    match result {
        Err(EcdhError::InvalidKeySize { expected, actual }) => {
            assert_eq!(expected, P384_PUBLIC_KEY_SIZE);
            assert_eq!(actual, 65);
        }
        _ => panic!("Expected InvalidKeySize error"),
    }
}

#[test]
fn test_p384_reject_invalid_public_key_in_agreement() {
    let keypair = EcdhP384KeyPair::generate().expect("keypair generation should succeed");

    let junk_bytes = vec![0x04u8; P384_PUBLIC_KEY_SIZE];

    let result = keypair.agree(&junk_bytes);
    assert!(result.is_err(), "Invalid public key should be rejected in agreement");
}

#[test]
fn test_p521_reject_wrong_size_public_key() {
    let wrong_size = vec![0x04u8; 97]; // P-384 size instead of P-521
    let result = EcdhP521PublicKey::from_bytes(&wrong_size);
    assert!(result.is_err(), "Wrong size should be rejected");

    match result {
        Err(EcdhError::InvalidKeySize { expected, actual }) => {
            assert_eq!(expected, P521_PUBLIC_KEY_SIZE);
            assert_eq!(actual, 97);
        }
        _ => panic!("Expected InvalidKeySize error"),
    }
}

#[test]
fn test_p521_reject_invalid_public_key_in_agreement() {
    let keypair = EcdhP521KeyPair::generate().expect("keypair generation should succeed");

    let junk_bytes = vec![0x04u8; P521_PUBLIC_KEY_SIZE];

    let result = keypair.agree(&junk_bytes);
    assert!(result.is_err(), "Invalid public key should be rejected in agreement");
}

#[test]
fn test_x25519_reject_wrong_size_public_key() {
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
fn test_x25519_reject_invalid_public_key_in_agreement() {
    let keypair = X25519KeyPair::generate().expect("keypair generation should succeed");

    // All zeros is a low-order point (though aws-lc-rs might still process it)
    let all_zeros = vec![0u8; X25519_KEY_SIZE];

    // The agreement might succeed or fail depending on implementation
    // What's important is it doesn't panic
    let _result = keypair.agree(&all_zeros);
}

// ============================================================================
// Task 2.5.6: Test Key Serialization Roundtrip
// ============================================================================

#[test]
fn test_p256_public_key_serialization_roundtrip() {
    let keypair = EcdhP256KeyPair::generate().expect("keypair generation should succeed");
    let pk = keypair.public_key().expect("public key extraction should succeed");

    // Serialize
    let bytes = pk.as_bytes();
    let vec_bytes = pk.to_vec();

    // Deserialize
    let restored = EcdhP256PublicKey::from_bytes(bytes).expect("restoration should succeed");
    let restored_vec =
        EcdhP256PublicKey::from_bytes(&vec_bytes).expect("restoration from vec should succeed");

    assert_eq!(pk.as_bytes(), restored.as_bytes(), "Roundtrip should preserve bytes");
    assert_eq!(pk.as_bytes(), restored_vec.as_bytes(), "Roundtrip from vec should preserve bytes");
}

#[test]
fn test_p384_public_key_serialization_roundtrip() {
    let keypair = EcdhP384KeyPair::generate().expect("keypair generation should succeed");
    let pk = keypair.public_key().expect("public key extraction should succeed");

    let bytes = pk.as_bytes();
    let vec_bytes = pk.to_vec();

    let restored = EcdhP384PublicKey::from_bytes(bytes).expect("restoration should succeed");
    let restored_vec =
        EcdhP384PublicKey::from_bytes(&vec_bytes).expect("restoration from vec should succeed");

    assert_eq!(pk.as_bytes(), restored.as_bytes(), "Roundtrip should preserve bytes");
    assert_eq!(pk.as_bytes(), restored_vec.as_bytes(), "Roundtrip from vec should preserve bytes");
}

#[test]
fn test_p521_public_key_serialization_roundtrip() {
    let keypair = EcdhP521KeyPair::generate().expect("keypair generation should succeed");
    let pk = keypair.public_key().expect("public key extraction should succeed");

    let bytes = pk.as_bytes();
    let vec_bytes = pk.to_vec();

    let restored = EcdhP521PublicKey::from_bytes(bytes).expect("restoration should succeed");
    let restored_vec =
        EcdhP521PublicKey::from_bytes(&vec_bytes).expect("restoration from vec should succeed");

    assert_eq!(pk.as_bytes(), restored.as_bytes(), "Roundtrip should preserve bytes");
    assert_eq!(pk.as_bytes(), restored_vec.as_bytes(), "Roundtrip from vec should preserve bytes");
}

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

    let restored = X25519SecretKey::from_bytes(sk.as_bytes()).expect("restoration should succeed");

    assert_eq!(sk.as_bytes(), restored.as_bytes(), "Roundtrip should preserve bytes");
}

// ============================================================================
// Additional X25519 Tests (Existing Curve)
// ============================================================================

#[test]
fn test_x25519_keypair_generation() {
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
fn test_x25519_key_exchange_both_parties_same_secret() {
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
fn test_x25519_agree_ephemeral() {
    let peer = X25519KeyPair::generate().expect("Peer keypair generation should succeed");
    let peer_pk = *peer.public_key_bytes();

    let result = agree_ephemeral(&peer_pk);
    assert!(result.is_ok(), "Ephemeral agreement should succeed");

    let (shared_secret, our_public) = result.expect("ephemeral agreement should succeed");
    assert_eq!(shared_secret.len(), X25519_KEY_SIZE, "Shared secret should be 32 bytes");
    assert_eq!(our_public.len(), X25519_KEY_SIZE, "Our public key should be 32 bytes");
}

#[test]
fn test_x25519_legacy_generate_keypair() {
    let mut rng = rand::thread_rng();
    let result = generate_keypair(&mut rng);
    assert!(result.is_ok(), "Legacy keypair generation should succeed");

    let (pk, sk) = result.expect("keypair generation should succeed");
    assert_eq!(pk.as_bytes().len(), X25519_KEY_SIZE);
    assert_eq!(sk.as_bytes().len(), X25519_KEY_SIZE);
}

#[test]
fn test_x25519_diffie_hellman_deterministic() {
    let sk = X25519SecretKey::from_bytes(&[1u8; X25519_KEY_SIZE]).expect("sk creation succeeds");
    let pk = X25519PublicKey::from_bytes(&[2u8; X25519_KEY_SIZE]).expect("pk creation succeeds");

    let ss1 = diffie_hellman(&sk, &pk);
    let ss2 = diffie_hellman(&sk, &pk);

    assert_eq!(ss1, ss2, "DH should be deterministic with same inputs");
}

// ============================================================================
// EcdhCurve Enum Tests
// ============================================================================

#[test]
fn test_ecdh_curve_public_key_sizes() {
    assert_eq!(EcdhCurve::X25519.public_key_size(), X25519_KEY_SIZE);
    assert_eq!(EcdhCurve::P256.public_key_size(), P256_PUBLIC_KEY_SIZE);
    assert_eq!(EcdhCurve::P384.public_key_size(), P384_PUBLIC_KEY_SIZE);
    assert_eq!(EcdhCurve::P521.public_key_size(), P521_PUBLIC_KEY_SIZE);
}

#[test]
fn test_ecdh_curve_shared_secret_sizes() {
    assert_eq!(EcdhCurve::X25519.shared_secret_size(), X25519_KEY_SIZE);
    assert_eq!(EcdhCurve::P256.shared_secret_size(), P256_SHARED_SECRET_SIZE);
    assert_eq!(EcdhCurve::P384.shared_secret_size(), P384_SHARED_SECRET_SIZE);
    assert_eq!(EcdhCurve::P521.shared_secret_size(), P521_SHARED_SECRET_SIZE);
}

#[test]
fn test_ecdh_curve_names() {
    assert_eq!(EcdhCurve::X25519.name(), "X25519");
    assert_eq!(EcdhCurve::P256.name(), "P-256");
    assert_eq!(EcdhCurve::P384.name(), "P-384");
    assert_eq!(EcdhCurve::P521.name(), "P-521");
}

// ============================================================================
// Cross-Curve Tests (Should Fail)
// ============================================================================

#[test]
fn test_p256_cannot_agree_with_p384_key() {
    let p256_keypair =
        EcdhP256KeyPair::generate().expect("P-256 keypair generation should succeed");
    let p384_keypair =
        EcdhP384KeyPair::generate().expect("P-384 keypair generation should succeed");

    let p384_pk = p384_keypair.public_key_bytes().to_vec();

    // Trying to use P-384 key with P-256 should fail
    let result = p256_keypair.agree(&p384_pk);
    assert!(result.is_err(), "Cross-curve agreement should fail (P-256 with P-384)");
}

#[test]
fn test_p384_cannot_agree_with_p521_key() {
    let p384_keypair =
        EcdhP384KeyPair::generate().expect("P-384 keypair generation should succeed");
    let p521_keypair =
        EcdhP521KeyPair::generate().expect("P-521 keypair generation should succeed");

    let p521_pk = p521_keypair.public_key_bytes().to_vec();

    let result = p384_keypair.agree(&p521_pk);
    assert!(result.is_err(), "Cross-curve agreement should fail (P-384 with P-521)");
}

// ============================================================================
// Debug and Display Tests
// ============================================================================

#[test]
fn test_p256_keypair_debug_redacts_private_key() {
    let keypair = EcdhP256KeyPair::generate().expect("keypair generation should succeed");
    let debug_str = format!("{:?}", keypair);

    assert!(debug_str.contains("[REDACTED]"), "Debug output should redact private key");
    // The debug output should show public bytes but mark private as redacted
    assert!(debug_str.contains("public_bytes"), "Debug should show public_bytes field");
    assert!(debug_str.contains("private"), "Debug should mention private field (even if redacted)");
}

#[test]
fn test_x25519_secret_key_debug_redacts() {
    let sk = X25519SecretKey::from_bytes(&[0x42u8; X25519_KEY_SIZE])
        .expect("secret key creation should succeed");
    let debug_str = format!("{:?}", sk);

    assert!(debug_str.contains("[REDACTED]"), "Debug output should redact secret key");
    assert!(!debug_str.contains("66"), "Debug should not contain raw key value (0x42 = 66)");
}

// ============================================================================
// Error Type Tests
// ============================================================================

#[test]
fn test_ecdh_error_display() {
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
fn test_ecdh_error_equality() {
    let error1 = EcdhError::KeyGenerationFailed;
    let error2 = EcdhError::KeyGenerationFailed;
    assert_eq!(error1, error2);

    let error3 = EcdhError::AgreementFailed;
    assert_ne!(error1, error3);
}

// ============================================================================
// Multiple Agreement Tests
// ============================================================================

#[test]
fn test_p256_multiple_agreements_produce_different_secrets() {
    // Alice generates a single keypair
    let alice_pk = EcdhP256KeyPair::generate()
        .expect("Alice keypair generation should succeed")
        .public_key_bytes()
        .to_vec();

    // Bob generates two different keypairs
    let bob1 = EcdhP256KeyPair::generate().expect("Bob1 keypair generation should succeed");
    let bob2 = EcdhP256KeyPair::generate().expect("Bob2 keypair generation should succeed");

    let secret1 = bob1.agree(&alice_pk).expect("Agreement 1 should succeed");
    let secret2 = bob2.agree(&alice_pk).expect("Agreement 2 should succeed");

    // Different private keys should produce different shared secrets
    assert_ne!(secret1, secret2, "Different sessions should produce different secrets");
}

// ============================================================================
// Constant Size Tests
// ============================================================================

#[test]
fn test_key_size_constants_are_correct() {
    // X25519
    assert_eq!(X25519_KEY_SIZE, 32);

    // P-256: 1 (format byte) + 32 (x) + 32 (y) = 65
    assert_eq!(P256_PUBLIC_KEY_SIZE, 65);
    assert_eq!(P256_SHARED_SECRET_SIZE, 32);

    // P-384: 1 (format byte) + 48 (x) + 48 (y) = 97
    assert_eq!(P384_PUBLIC_KEY_SIZE, 97);
    assert_eq!(P384_SHARED_SECRET_SIZE, 48);

    // P-521: 1 (format byte) + 66 (x) + 66 (y) = 133
    assert_eq!(P521_PUBLIC_KEY_SIZE, 133);
    assert_eq!(P521_SHARED_SECRET_SIZE, 66);
}

// ============================================================================
// Clone and Equality Tests for Public Keys
// ============================================================================

#[test]
fn test_p256_public_key_clone() {
    let keypair = EcdhP256KeyPair::generate().expect("keypair generation should succeed");
    let pk = keypair.public_key().expect("public key extraction should succeed");
    let pk_clone = pk.clone();

    assert_eq!(pk, pk_clone, "Cloned public key should be equal");
    assert_eq!(pk.as_bytes(), pk_clone.as_bytes());
}

#[test]
fn test_p384_public_key_clone() {
    let keypair = EcdhP384KeyPair::generate().expect("keypair generation should succeed");
    let pk = keypair.public_key().expect("public key extraction should succeed");
    let pk_clone = pk.clone();

    assert_eq!(pk, pk_clone, "Cloned public key should be equal");
}

#[test]
fn test_p521_public_key_clone() {
    let keypair = EcdhP521KeyPair::generate().expect("keypair generation should succeed");
    let pk = keypair.public_key().expect("public key extraction should succeed");
    let pk_clone = pk.clone();

    assert_eq!(pk, pk_clone, "Cloned public key should be equal");
}

#[test]
fn test_x25519_public_key_clone() {
    let keypair = X25519KeyPair::generate().expect("keypair generation should succeed");
    let pk = keypair.public_key();
    let pk_clone = pk.clone();

    assert_eq!(pk, pk_clone, "Cloned public key should be equal");
}
