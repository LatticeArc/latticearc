//! Hybrid KEM Deterministic Verification Tests
//!
//! Verifies the hybrid KEM shared secret derivation logic by independently
//! computing the expected HKDF-SHA256 output using the `hkdf` crate (pure Rust)
//! and comparing against `derive_hybrid_shared_secret()` (which uses aws-lc-rs).
//!
//! This is the most critical verification because the hybrid combination is our
//! own construction (not a NIST standard), making it the part most likely to
//! have bugs.
//!
//! What this tests:
//! 1. HKDF derivation correctness against an independent implementation
//! 2. Domain separator "LatticeArc-Hybrid-KEM-SS" is included in info
//! 3. IKM is ml_kem_ss || ecdh_ss (not reversed)
//! 4. Roundtrip determinism (same inputs → same output every time)

#![allow(missing_docs)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use hkdf::Hkdf;
use latticearc::hybrid::kem::derive_hybrid_shared_secret;
use sha2::Sha256;

/// Fixed test vectors for deterministic verification.
const ML_KEM_SS: [u8; 32] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
];

const ECDH_SS: [u8; 32] = [
    0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0,
    0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf, 0xc0,
];

const STATIC_PK: [u8; 32] = [
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
    0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0, 0x01,
];

const EPHEMERAL_PK: [u8; 32] = [
    0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b, 0x3c, 0x2d, 0x1e, 0x0f,
];

/// Independently compute the expected hybrid shared secret using the `hkdf` crate.
///
/// This replicates the exact logic from `derive_hybrid_shared_secret` but uses
/// a completely different HKDF implementation (pure-Rust `hkdf` crate with
/// `sha2` instead of aws-lc-rs).
fn independent_hkdf(
    ml_kem_ss: &[u8],
    ecdh_ss: &[u8],
    static_pk: &[u8],
    ephemeral_pk: &[u8],
) -> Vec<u8> {
    // IKM = ml_kem_ss || ecdh_ss
    let mut ikm = Vec::with_capacity(64);
    ikm.extend_from_slice(ml_kem_ss);
    ikm.extend_from_slice(ecdh_ss);

    // Info = "LatticeArc-Hybrid-KEM-SS" || "||" || static_pk || "||" || ephemeral_pk
    let mut info = Vec::new();
    info.extend_from_slice(b"LatticeArc-Hybrid-KEM-SS");
    info.extend_from_slice(b"||");
    info.extend_from_slice(static_pk);
    info.extend_from_slice(b"||");
    info.extend_from_slice(ephemeral_pk);

    // HKDF-SHA256 with no salt (defaults to 32 zero bytes per RFC 5869)
    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut output = vec![0u8; 64];
    hk.expand(&info, &mut output).expect("HKDF expand should succeed for 64-byte output");
    output
}

/// Core test: verify derive_hybrid_shared_secret matches independent HKDF.
#[test]
fn test_hybrid_kdf_matches_independent_hkdf() {
    let actual =
        derive_hybrid_shared_secret(&ML_KEM_SS, &ECDH_SS, &STATIC_PK, &EPHEMERAL_PK).unwrap();

    let expected = independent_hkdf(&ML_KEM_SS, &ECDH_SS, &STATIC_PK, &EPHEMERAL_PK);

    assert_eq!(
        actual, expected,
        "derive_hybrid_shared_secret must match independent HKDF computation"
    );
}

/// Verify output is exactly 64 bytes (two SHA-256 blocks).
#[test]
fn test_hybrid_kdf_output_length() {
    let result =
        derive_hybrid_shared_secret(&ML_KEM_SS, &ECDH_SS, &STATIC_PK, &EPHEMERAL_PK).unwrap();

    assert_eq!(result.len(), 64, "Hybrid shared secret must be 64 bytes");
}

/// Verify domain separator is included by checking that our output differs
/// from a raw HKDF with no info string.
#[test]
fn test_domain_separator_affects_output() {
    let with_domain =
        derive_hybrid_shared_secret(&ML_KEM_SS, &ECDH_SS, &STATIC_PK, &EPHEMERAL_PK).unwrap();

    // Compute HKDF with same IKM but empty info
    let mut ikm = Vec::with_capacity(64);
    ikm.extend_from_slice(&ML_KEM_SS);
    ikm.extend_from_slice(&ECDH_SS);

    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut without_domain = vec![0u8; 64];
    hk.expand(&[], &mut without_domain).expect("HKDF expand should succeed");

    assert_ne!(with_domain, without_domain, "Domain separator must affect the output");
}

/// Verify IKM ordering: ml_kem_ss || ecdh_ss (not reversed).
///
/// Swapping the inputs should produce a different shared secret.
#[test]
fn test_ikm_ordering_ml_kem_first() {
    let correct_order =
        derive_hybrid_shared_secret(&ML_KEM_SS, &ECDH_SS, &STATIC_PK, &EPHEMERAL_PK).unwrap();

    // Swap ml_kem_ss and ecdh_ss
    let reversed_order =
        derive_hybrid_shared_secret(&ECDH_SS, &ML_KEM_SS, &STATIC_PK, &EPHEMERAL_PK).unwrap();

    assert_ne!(
        correct_order, reversed_order,
        "Swapping ML-KEM and ECDH shared secrets must produce different output"
    );
}

/// Verify the correct ordering matches independent computation.
#[test]
fn test_ikm_ordering_matches_spec() {
    let actual =
        derive_hybrid_shared_secret(&ML_KEM_SS, &ECDH_SS, &STATIC_PK, &EPHEMERAL_PK).unwrap();

    // Build IKM in the expected order: ml_kem_ss first
    let mut ikm_correct = Vec::with_capacity(64);
    ikm_correct.extend_from_slice(&ML_KEM_SS);
    ikm_correct.extend_from_slice(&ECDH_SS);

    let mut info = Vec::new();
    info.extend_from_slice(b"LatticeArc-Hybrid-KEM-SS");
    info.extend_from_slice(b"||");
    info.extend_from_slice(&STATIC_PK);
    info.extend_from_slice(b"||");
    info.extend_from_slice(&EPHEMERAL_PK);

    let hk = Hkdf::<Sha256>::new(None, &ikm_correct);
    let mut expected = vec![0u8; 64];
    hk.expand(&info, &mut expected).unwrap();

    assert_eq!(actual, expected, "IKM ordering must be ml_kem_ss || ecdh_ss");

    // Verify reversed IKM does NOT match
    let mut ikm_reversed = Vec::with_capacity(64);
    ikm_reversed.extend_from_slice(&ECDH_SS);
    ikm_reversed.extend_from_slice(&ML_KEM_SS);

    let hk_rev = Hkdf::<Sha256>::new(None, &ikm_reversed);
    let mut reversed = vec![0u8; 64];
    hk_rev.expand(&info, &mut reversed).unwrap();

    assert_ne!(actual, reversed, "Reversed IKM must not match correct order");
}

/// Verify static_pk is bound into the derivation (context binding).
#[test]
fn test_static_pk_binding() {
    let result1 =
        derive_hybrid_shared_secret(&ML_KEM_SS, &ECDH_SS, &STATIC_PK, &EPHEMERAL_PK).unwrap();

    let mut different_pk = STATIC_PK;
    different_pk[0] ^= 0xFF;

    let result2 =
        derive_hybrid_shared_secret(&ML_KEM_SS, &ECDH_SS, &different_pk, &EPHEMERAL_PK).unwrap();

    assert_ne!(
        result1, result2,
        "Different static public keys must produce different shared secrets"
    );
}

/// Verify ephemeral_pk is bound into the derivation (context binding).
#[test]
fn test_ephemeral_pk_binding() {
    let result1 =
        derive_hybrid_shared_secret(&ML_KEM_SS, &ECDH_SS, &STATIC_PK, &EPHEMERAL_PK).unwrap();

    let mut different_epk = EPHEMERAL_PK;
    different_epk[0] ^= 0xFF;

    let result2 =
        derive_hybrid_shared_secret(&ML_KEM_SS, &ECDH_SS, &STATIC_PK, &different_epk).unwrap();

    assert_ne!(
        result1, result2,
        "Different ephemeral public keys must produce different shared secrets"
    );
}

/// Determinism: same inputs produce identical output across 100 invocations.
#[test]
fn test_roundtrip_determinism() {
    let reference =
        derive_hybrid_shared_secret(&ML_KEM_SS, &ECDH_SS, &STATIC_PK, &EPHEMERAL_PK).unwrap();

    for i in 0..100 {
        let result =
            derive_hybrid_shared_secret(&ML_KEM_SS, &ECDH_SS, &STATIC_PK, &EPHEMERAL_PK).unwrap();
        assert_eq!(reference, result, "Output must be deterministic (mismatch at iteration {})", i);
    }
}

/// Verify error handling: ML-KEM shared secret must be exactly 32 bytes.
#[test]
fn test_invalid_ml_kem_ss_length() {
    let short_ss = [0u8; 16];
    let result = derive_hybrid_shared_secret(&short_ss, &ECDH_SS, &STATIC_PK, &EPHEMERAL_PK);
    assert!(result.is_err(), "16-byte ML-KEM SS should be rejected");

    let long_ss = [0u8; 64];
    let result = derive_hybrid_shared_secret(&long_ss, &ECDH_SS, &STATIC_PK, &EPHEMERAL_PK);
    assert!(result.is_err(), "64-byte ML-KEM SS should be rejected");
}

/// Verify error handling: ECDH shared secret must be exactly 32 bytes.
#[test]
fn test_invalid_ecdh_ss_length() {
    let short_ss = [0u8; 16];
    let result = derive_hybrid_shared_secret(&ML_KEM_SS, &short_ss, &STATIC_PK, &EPHEMERAL_PK);
    assert!(result.is_err(), "16-byte ECDH SS should be rejected");

    let long_ss = [0u8; 64];
    let result = derive_hybrid_shared_secret(&ML_KEM_SS, &long_ss, &STATIC_PK, &EPHEMERAL_PK);
    assert!(result.is_err(), "64-byte ECDH SS should be rejected");
}

/// Verify the derivation produces non-trivial output (not all zeros).
#[test]
fn test_output_is_nontrivial() {
    let result =
        derive_hybrid_shared_secret(&ML_KEM_SS, &ECDH_SS, &STATIC_PK, &EPHEMERAL_PK).unwrap();
    assert!(!result.iter().all(|&b| b == 0), "Shared secret must not be all zeros");
}

/// Full hybrid KEM roundtrip: generate keys, encapsulate, decapsulate,
/// verify shared secrets match. Repeat to confirm determinism of the
/// encapsulate/decapsulate flow (even though keygen is random each time).
#[test]
fn test_full_roundtrip_shared_secret_agreement() {
    use latticearc::hybrid::kem::{decapsulate, encapsulate, generate_keypair};
    use rand::thread_rng;

    for _ in 0..10 {
        let mut rng = thread_rng();
        let (pk, sk) = generate_keypair(&mut rng).unwrap();

        let encapsulated = encapsulate(&mut rng, &pk).unwrap();

        let decapsulated_ss = decapsulate(&sk, &encapsulated).unwrap();

        assert_eq!(
            encapsulated.shared_secret.as_slice(),
            decapsulated_ss.as_slice(),
            "Encapsulated and decapsulated shared secrets must match"
        );
    }
}
