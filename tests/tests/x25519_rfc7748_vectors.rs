//! X25519 RFC 7748 Test Vectors
//!
//! Validates our X25519 implementation (via aws-lc-rs) against the IETF
//! RFC 7748 Section 6.1 test vectors. This verifies the classical component
//! of our hybrid KEM.
//!
//! Test vectors:
//! 1. Alice ↔ Bob key exchange with known scalars and public keys
//! 2. Iterative DH test (1,000 iterations of self-DH)
//!
//! Reference: <https://datatracker.ietf.org/doc/html/rfc7748#section-6.1>

#![allow(missing_docs)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use latticearc::primitives::kem::ecdh::X25519StaticKeyPair;

/// RFC 7748 Section 6.1 — Alice's private key (scalar)
const ALICE_SCALAR: [u8; 32] = [
    0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
    0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a,
];

/// RFC 7748 Section 6.1 — Alice's public key (computed from scalar)
const ALICE_PUBLIC: [u8; 32] = [
    0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54, 0x74, 0x8b, 0x7d, 0xdc, 0xb4, 0x3e, 0xf7, 0x5a,
    0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38, 0x1a, 0xf4, 0xeb, 0xa4, 0xa9, 0x8e, 0xaa, 0x9b, 0x4e, 0x6a,
];

/// RFC 7748 Section 6.1 — Bob's private key (scalar)
const BOB_SCALAR: [u8; 32] = [
    0x5d, 0xab, 0x08, 0x7e, 0x62, 0x4a, 0x8a, 0x4b, 0x79, 0xe1, 0x7f, 0x8b, 0x83, 0x80, 0x0e, 0xe6,
    0x6f, 0x3b, 0xb1, 0x29, 0x26, 0x18, 0xb6, 0xfd, 0x1c, 0x2f, 0x8b, 0x27, 0xff, 0x88, 0xe0, 0xeb,
];

/// RFC 7748 Section 6.1 — Bob's public key (computed from scalar)
const BOB_PUBLIC: [u8; 32] = [
    0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4, 0xd3, 0x5b, 0x61, 0xc2, 0xec, 0xe4, 0x35, 0x37,
    0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78, 0x67, 0x4d, 0xad, 0xfc, 0x7e, 0x14, 0x6f, 0x88, 0x2b, 0x4f,
];

/// RFC 7748 Section 6.1 — Shared secret (Alice DH with Bob's public key)
const SHARED_SECRET: [u8; 32] = [
    0x4a, 0x5d, 0x9d, 0x5b, 0xa4, 0xce, 0x2d, 0xe1, 0x72, 0x8e, 0x3b, 0xf4, 0x80, 0x35, 0x0f, 0x25,
    0xe0, 0x7e, 0x21, 0xc9, 0x47, 0xd1, 0x9e, 0x33, 0x76, 0xf0, 0x9b, 0x3c, 0x1e, 0x16, 0x17, 0x42,
];

/// Test 1: Alice's public key derivation from her scalar.
#[test]
fn test_alice_public_key_from_scalar() {
    let alice = X25519StaticKeyPair::from_seed_bytes(&ALICE_SCALAR)
        .expect("Alice's key pair should be valid");

    assert_eq!(
        alice.public_key_bytes(),
        &ALICE_PUBLIC,
        "Alice's public key must match RFC 7748 §6.1 test vector"
    );
}

/// Test 2: Bob's public key derivation from his scalar.
#[test]
fn test_bob_public_key_from_scalar() {
    let bob =
        X25519StaticKeyPair::from_seed_bytes(&BOB_SCALAR).expect("Bob's key pair should be valid");

    assert_eq!(
        bob.public_key_bytes(),
        &BOB_PUBLIC,
        "Bob's public key must match RFC 7748 §6.1 test vector"
    );
}

/// Test 3: Alice computes shared secret with Bob's public key.
#[test]
fn test_alice_shared_secret() {
    let alice = X25519StaticKeyPair::from_seed_bytes(&ALICE_SCALAR)
        .expect("Alice's key pair should be valid");

    let shared = alice.agree(&BOB_PUBLIC).expect("Key agreement should succeed");

    assert_eq!(shared, SHARED_SECRET, "Alice's shared secret must match RFC 7748 §6.1 test vector");
}

/// Test 4: Bob computes the same shared secret with Alice's public key.
#[test]
fn test_bob_shared_secret() {
    let bob =
        X25519StaticKeyPair::from_seed_bytes(&BOB_SCALAR).expect("Bob's key pair should be valid");

    let shared = bob.agree(&ALICE_PUBLIC).expect("Key agreement should succeed");

    assert_eq!(shared, SHARED_SECRET, "Bob's shared secret must match RFC 7748 §6.1 test vector");
}

/// Test 5: Bidirectional agreement — Alice and Bob compute the same secret.
#[test]
fn test_bidirectional_agreement() {
    let alice = X25519StaticKeyPair::from_seed_bytes(&ALICE_SCALAR)
        .expect("Alice's key pair should be valid");
    let bob =
        X25519StaticKeyPair::from_seed_bytes(&BOB_SCALAR).expect("Bob's key pair should be valid");

    let alice_shared =
        alice.agree(bob.public_key_bytes()).expect("Alice→Bob agreement should succeed");
    let bob_shared =
        bob.agree(alice.public_key_bytes()).expect("Bob→Alice agreement should succeed");

    assert_eq!(
        alice_shared, bob_shared,
        "Bidirectional key agreement must produce identical shared secrets"
    );
    assert_eq!(alice_shared, SHARED_SECRET, "Both must match the RFC 7748 test vector");
}

/// RFC 7748 Section 6.1 — Iterative X25519 test.
///
/// Starting with k = u = 0x09...00 (the basepoint), iteratively compute:
///   k, u = X25519(k, u), k
///
/// After 1 iteration:
///   k = 422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079
///
/// After 1,000 iterations:
///   k = 684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51
#[test]
fn test_iterative_dh_1() {
    let mut k = [0u8; 32];
    k[0] = 9; // Basepoint
    let mut u = [0u8; 32];
    u[0] = 9;

    let key = X25519StaticKeyPair::from_seed_bytes(&k).expect("key from basepoint should work");
    let new_k = key.agree(&u).expect("DH with basepoint should succeed");

    let expected_after_1 =
        hex::decode("422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079")
            .expect("valid hex");

    assert_eq!(
        new_k.as_ref(),
        expected_after_1.as_slice(),
        "After 1 iteration, k must match RFC 7748 test vector"
    );
}

/// RFC 7748 Section 6.1 — Iterative DH after 1,000 iterations.
#[test]
fn test_iterative_dh_1000() {
    let mut k = [0u8; 32];
    k[0] = 9;
    let mut u = [0u8; 32];
    u[0] = 9;

    for _ in 0..1000 {
        let key =
            X25519StaticKeyPair::from_seed_bytes(&k).expect("key construction should succeed");
        let new_k = key.agree(&u).expect("DH should succeed");
        u = k;
        k = new_k;
    }

    let expected_after_1000 =
        hex::decode("684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51")
            .expect("valid hex");

    assert_eq!(
        k.as_ref(),
        expected_after_1000.as_slice(),
        "After 1,000 iterations, k must match RFC 7748 test vector"
    );
}
