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
use latticearc::hybrid::{HybridSharedSecretInputs, derive_hybrid_shared_secret};
use sha2::Sha256;
use subtle::ConstantTimeEq;

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
///
/// The `info` input uses HPKE §5.1 / RFC 9180 length-prefix encoding for
/// unambiguous concatenation:
///   info = domain_label || u32_be(static_pk.len()) || static_pk
///        || u32_be(ephemeral_pk.len()) || ephemeral_pk
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

    // Info = domain_label || len(static_pk) || static_pk || len(eph_pk) || eph_pk
    let mut info = Vec::new();
    info.extend_from_slice(b"LatticeArc-Hybrid-KEM-SS");
    let static_pk_len = u32::try_from(static_pk.len()).expect("public key within u32 range");
    info.extend_from_slice(&static_pk_len.to_be_bytes());
    info.extend_from_slice(static_pk);
    let ephemeral_pk_len = u32::try_from(ephemeral_pk.len()).expect("public key within u32 range");
    info.extend_from_slice(&ephemeral_pk_len.to_be_bytes());
    info.extend_from_slice(ephemeral_pk);

    // HKDF-SHA256 with no salt (defaults to 32 zero bytes per RFC 5869)
    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut output = vec![0u8; 64];
    hk.expand(&info, &mut output).expect("HKDF expand should succeed for 64-byte output");
    output
}

/// Core test: verify derive_hybrid_shared_secret matches independent HKDF.
#[test]
fn test_hybrid_kdf_matches_independent_hkdf_succeeds() {
    let actual = derive_hybrid_shared_secret(HybridSharedSecretInputs {
        ml_kem_ss: &ML_KEM_SS,
        ecdh_ss: &ECDH_SS,
        static_pk: &STATIC_PK,
        ephemeral_pk: &EPHEMERAL_PK,
    })
    .unwrap();

    let expected = independent_hkdf(&ML_KEM_SS, &ECDH_SS, &STATIC_PK, &EPHEMERAL_PK);

    assert_eq!(
        actual.expose_secret(),
        expected.as_slice(),
        "derive_hybrid_shared_secret must match independent HKDF computation"
    );
}

/// Verify output is exactly 64 bytes (two SHA-256 blocks).
#[test]
fn test_hybrid_kdf_output_length_has_correct_size() {
    let result = derive_hybrid_shared_secret(HybridSharedSecretInputs {
        ml_kem_ss: &ML_KEM_SS,
        ecdh_ss: &ECDH_SS,
        static_pk: &STATIC_PK,
        ephemeral_pk: &EPHEMERAL_PK,
    })
    .unwrap();

    assert_eq!(result.len(), 64, "Hybrid shared secret must be 64 bytes");
}

/// Verify domain separator is included by checking that our output differs
/// from a raw HKDF with no info string.
#[test]
fn test_domain_separator_affects_output_produces_different_secret_succeeds() {
    let with_domain = derive_hybrid_shared_secret(HybridSharedSecretInputs {
        ml_kem_ss: &ML_KEM_SS,
        ecdh_ss: &ECDH_SS,
        static_pk: &STATIC_PK,
        ephemeral_pk: &EPHEMERAL_PK,
    })
    .unwrap();

    // Compute HKDF with same IKM but empty info
    let mut ikm = Vec::with_capacity(64);
    ikm.extend_from_slice(&ML_KEM_SS);
    ikm.extend_from_slice(&ECDH_SS);

    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut without_domain = vec![0u8; 64];
    hk.expand(&[], &mut without_domain).expect("HKDF expand should succeed");

    assert_ne!(
        with_domain.expose_secret(),
        without_domain.as_slice(),
        "Domain separator must affect the output"
    );
}

/// Verify IKM ordering: ml_kem_ss || ecdh_ss (not reversed).
///
/// Swapping the inputs should produce a different shared secret.
#[test]
fn test_ikm_ordering_ml_kem_first_produces_different_output_when_swapped_succeeds() {
    let correct_order = derive_hybrid_shared_secret(HybridSharedSecretInputs {
        ml_kem_ss: &ML_KEM_SS,
        ecdh_ss: &ECDH_SS,
        static_pk: &STATIC_PK,
        ephemeral_pk: &EPHEMERAL_PK,
    })
    .unwrap();

    // Swap ml_kem_ss and ecdh_ss
    let reversed_order = derive_hybrid_shared_secret(HybridSharedSecretInputs {
        ml_kem_ss: &ECDH_SS,
        ecdh_ss: &ML_KEM_SS,
        static_pk: &STATIC_PK,
        ephemeral_pk: &EPHEMERAL_PK,
    })
    .unwrap();

    assert_ne!(
        correct_order.expose_secret(),
        reversed_order.expose_secret(),
        "Swapping ML-KEM and ECDH shared secrets must produce different output"
    );
}

/// Verify the correct ordering matches independent computation.
#[test]
fn test_ikm_ordering_matches_spec_succeeds() {
    let actual = derive_hybrid_shared_secret(HybridSharedSecretInputs {
        ml_kem_ss: &ML_KEM_SS,
        ecdh_ss: &ECDH_SS,
        static_pk: &STATIC_PK,
        ephemeral_pk: &EPHEMERAL_PK,
    })
    .unwrap();

    // Build IKM in the expected order: ml_kem_ss first
    let mut ikm_correct = Vec::with_capacity(64);
    ikm_correct.extend_from_slice(&ML_KEM_SS);
    ikm_correct.extend_from_slice(&ECDH_SS);

    // Info uses HPKE §5.1 / RFC 9180 length-prefix encoding (matches A1 fix).
    let mut info = Vec::new();
    info.extend_from_slice(b"LatticeArc-Hybrid-KEM-SS");
    let static_pk_len = u32::try_from(STATIC_PK.len()).expect("public key within u32 range");
    info.extend_from_slice(&static_pk_len.to_be_bytes());
    info.extend_from_slice(&STATIC_PK);
    let eph_pk_len = u32::try_from(EPHEMERAL_PK.len()).expect("public key within u32 range");
    info.extend_from_slice(&eph_pk_len.to_be_bytes());
    info.extend_from_slice(&EPHEMERAL_PK);

    let hk = Hkdf::<Sha256>::new(None, &ikm_correct);
    let mut expected = vec![0u8; 64];
    hk.expand(&info, &mut expected).unwrap();

    assert_eq!(
        actual.expose_secret(),
        expected.as_slice(),
        "IKM ordering must be ml_kem_ss || ecdh_ss"
    );

    // Verify reversed IKM does NOT match
    let mut ikm_reversed = Vec::with_capacity(64);
    ikm_reversed.extend_from_slice(&ECDH_SS);
    ikm_reversed.extend_from_slice(&ML_KEM_SS);

    let hk_rev = Hkdf::<Sha256>::new(None, &ikm_reversed);
    let mut reversed = vec![0u8; 64];
    hk_rev.expand(&info, &mut reversed).unwrap();

    assert_ne!(
        actual.expose_secret(),
        reversed.as_slice(),
        "Reversed IKM must not match correct order"
    );
}

/// Verify static_pk is bound into the derivation (context binding).
#[test]
fn test_static_pk_binding_produces_different_output_for_different_keys_succeeds() {
    let result1 = derive_hybrid_shared_secret(HybridSharedSecretInputs {
        ml_kem_ss: &ML_KEM_SS,
        ecdh_ss: &ECDH_SS,
        static_pk: &STATIC_PK,
        ephemeral_pk: &EPHEMERAL_PK,
    })
    .unwrap();

    let mut different_pk = STATIC_PK;
    different_pk[0] ^= 0xFF;

    let result2 = derive_hybrid_shared_secret(HybridSharedSecretInputs {
        ml_kem_ss: &ML_KEM_SS,
        ecdh_ss: &ECDH_SS,
        static_pk: &different_pk,
        ephemeral_pk: &EPHEMERAL_PK,
    })
    .unwrap();

    assert!(
        !bool::from(result1.ct_eq(&result2)),
        "Different static public keys must produce different shared secrets"
    );
}

/// Verify ephemeral_pk is bound into the derivation (context binding).
#[test]
fn test_ephemeral_pk_binding_produces_different_output_for_different_keys_succeeds() {
    let result1 = derive_hybrid_shared_secret(HybridSharedSecretInputs {
        ml_kem_ss: &ML_KEM_SS,
        ecdh_ss: &ECDH_SS,
        static_pk: &STATIC_PK,
        ephemeral_pk: &EPHEMERAL_PK,
    })
    .unwrap();

    let mut different_epk = EPHEMERAL_PK;
    different_epk[0] ^= 0xFF;

    let result2 = derive_hybrid_shared_secret(HybridSharedSecretInputs {
        ml_kem_ss: &ML_KEM_SS,
        ecdh_ss: &ECDH_SS,
        static_pk: &STATIC_PK,
        ephemeral_pk: &different_epk,
    })
    .unwrap();

    assert!(
        !bool::from(result1.ct_eq(&result2)),
        "Different ephemeral public keys must produce different shared secrets"
    );
}

/// Determinism: same inputs produce identical output across 100 invocations.
#[test]
fn test_roundtrip_determinism_roundtrip() {
    let reference = derive_hybrid_shared_secret(HybridSharedSecretInputs {
        ml_kem_ss: &ML_KEM_SS,
        ecdh_ss: &ECDH_SS,
        static_pk: &STATIC_PK,
        ephemeral_pk: &EPHEMERAL_PK,
    })
    .unwrap();

    for i in 0..100 {
        let result = derive_hybrid_shared_secret(HybridSharedSecretInputs {
            ml_kem_ss: &ML_KEM_SS,
            ecdh_ss: &ECDH_SS,
            static_pk: &STATIC_PK,
            ephemeral_pk: &EPHEMERAL_PK,
        })
        .unwrap();
        assert!(
            bool::from(reference.ct_eq(&result)),
            "Output must be deterministic (mismatch at iteration {})",
            i
        );
    }
}

/// Verify error handling: ML-KEM shared secret must be exactly 32 bytes.
#[test]
fn test_invalid_ml_kem_ss_length_fails() {
    let short_ss = [0u8; 16];
    let result = derive_hybrid_shared_secret(HybridSharedSecretInputs {
        ml_kem_ss: &short_ss,
        ecdh_ss: &ECDH_SS,
        static_pk: &STATIC_PK,
        ephemeral_pk: &EPHEMERAL_PK,
    });
    assert!(result.is_err(), "16-byte ML-KEM SS should be rejected");

    let long_ss = [0u8; 64];
    let result = derive_hybrid_shared_secret(HybridSharedSecretInputs {
        ml_kem_ss: &long_ss,
        ecdh_ss: &ECDH_SS,
        static_pk: &STATIC_PK,
        ephemeral_pk: &EPHEMERAL_PK,
    });
    assert!(result.is_err(), "64-byte ML-KEM SS should be rejected");
}

/// Verify error handling: ECDH shared secret must be exactly 32 bytes.
#[test]
fn test_invalid_ecdh_ss_length_fails() {
    let short_ss = [0u8; 16];
    let result = derive_hybrid_shared_secret(HybridSharedSecretInputs {
        ml_kem_ss: &ML_KEM_SS,
        ecdh_ss: &short_ss,
        static_pk: &STATIC_PK,
        ephemeral_pk: &EPHEMERAL_PK,
    });
    assert!(result.is_err(), "16-byte ECDH SS should be rejected");

    let long_ss = [0u8; 64];
    let result = derive_hybrid_shared_secret(HybridSharedSecretInputs {
        ml_kem_ss: &ML_KEM_SS,
        ecdh_ss: &long_ss,
        static_pk: &STATIC_PK,
        ephemeral_pk: &EPHEMERAL_PK,
    });
    assert!(result.is_err(), "64-byte ECDH SS should be rejected");
}

/// Verify the derivation produces non-trivial output (not all zeros).
#[test]
fn test_output_is_nontrivial_succeeds() {
    let result = derive_hybrid_shared_secret(HybridSharedSecretInputs {
        ml_kem_ss: &ML_KEM_SS,
        ecdh_ss: &ECDH_SS,
        static_pk: &STATIC_PK,
        ephemeral_pk: &EPHEMERAL_PK,
    })
    .unwrap();
    assert!(!result.expose_secret().iter().all(|&b| b == 0), "Shared secret must not be all zeros");
}

/// Full hybrid KEM roundtrip: generate keys, encapsulate, decapsulate,
/// verify shared secrets match. Repeat to confirm determinism of the
/// encapsulate/decapsulate flow (even though keygen is random each time).
#[test]
fn test_full_roundtrip_shared_secret_agreement_roundtrip() {
    use latticearc::hybrid::{decapsulate, encapsulate, kem_generate_keypair as generate_keypair};

    for _ in 0..10 {
        let (pk, sk) = generate_keypair().unwrap();

        let encapsulated = encapsulate(&pk).unwrap();

        let decapsulated_ss = decapsulate(&sk, &encapsulated).unwrap();

        assert_eq!(
            encapsulated.expose_secret(),
            decapsulated_ss.expose_secret(),
            "Encapsulated and decapsulated shared secrets must match"
        );
    }
}
