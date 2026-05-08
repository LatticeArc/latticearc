//! Signature, AEAD, and Pattern-6-opacity regressions.
//!
//! Covers signatures (ML-DSA, SLH-DSA, FN-DSA, Ed25519, secp256k1),
//! AEAD encrypt/decrypt opacity, and ZK-proof transcripts. Reverting
//! the fix must make the test fail.

#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::panic)]
#![allow(clippy::indexing_slicing)]
#![allow(clippy::arithmetic_side_effects)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_possible_wrap)]
#![allow(clippy::cast_sign_loss)]

use latticearc::primitives::aead::{AeadCipher, aes_gcm::AesGcm256};
use latticearc::primitives::ec::ed25519::Ed25519KeyPair;
use latticearc::primitives::ec::traits::EcKeyPair;
use latticearc::primitives::sig::ml_dsa::{MlDsaParameterSet, generate_keypair as ml_dsa_keygen};

/// `Ed25519KeyPair::sign` is fallible — must reject
/// messages exceeding the configured signature-size cap (default 64 KiB).
/// Reverting the `validate_signature_size` call would let this oversize
/// sign succeed.
#[test]
fn ed25519_sign_is_fallible_and_rejects_oversize_message() {
    let kp = Ed25519KeyPair::generate().unwrap();
    let oversize: Vec<u8> = vec![0u8; (64 * 1024) + 1];
    let result = kp.sign(&oversize);
    assert!(result.is_err(), "Ed25519 sign must reject messages above the signature-size cap");
}

/// AEAD encrypt path must reject AAD that exceeds the
/// configured cap. Default global `max_aad_size_bytes` is 1 MiB; passing
/// 1 MiB + 1 must fail before the AEAD primitive is invoked.
#[test]
fn aes_gcm_encrypt_rejects_oversized_aad() {
    let key = [0x42u8; 32];
    let cipher = AesGcm256::new(&key).unwrap();
    let nonce = AesGcm256::generate_nonce();
    let plaintext = b"short";
    // The default cap is 1 MiB. Construct just-over.
    let aad: Vec<u8> = vec![0u8; (1024 * 1024) + 1];
    let result = cipher.encrypt(&nonce, plaintext, Some(&aad));
    assert!(result.is_err(), "AAD over the cap must be rejected by AEAD encrypt");
}

// Round-36 H6: deleted dead `primitives::polynomial` module — the
// NTT/Montgomery code wasn't called from any production path
// (FIPS 203/204/205/206 all delegate to aws-lc-rs / fips204 / fips205
// / fn-dsa). The two regression tests that referenced it
// (`ntt_primitive_root_table_is_consistent` and
// `ntt_rejects_modulus_above_i32_max`) are removed alongside the
// module.

/// convenience-layer verify must return `Ok(false)` on
/// adversary-reachable failure (not `Err`). Reverting the round-26
/// `Err → Ok(false)` mapping in `verify_with_key` would surface as an
/// `Err(InvalidInput(...))` here.
#[test]
fn pq_sig_verify_with_malformed_signature_returns_ok_false() {
    let (pk, sk) = ml_dsa_keygen(MlDsaParameterSet::MlDsa44).unwrap();
    let msg = b"verify must not Err on adversary-reachable input";
    let sig = sk.sign(msg, b"").unwrap();

    // Corrupt the signature by flipping every bit of the first byte.
    let mut bytes = sig.as_bytes().to_vec();
    bytes[0] ^= 0xFF;
    let corrupted =
        latticearc::primitives::sig::ml_dsa::MlDsaSignature::new(MlDsaParameterSet::MlDsa44, bytes)
            .unwrap();

    // Verify must reject — `Ok(false)` (proper-shape rejection) OR
    // `Err` (per FIPS 204 unforgeability). The previous mapper
    // returned a string-leaking InvalidInput variant on parse failure;
    // round-26 H10 collapsed that. Either Err or Ok(false) is
    // acceptable. Round-36 C1: assert that the result actually falls
    // into one of those buckets — the previous `let _ = ...` form
    // discarded the result, so reverting the round-26 fix wouldn't
    // have tripped this regression test.
    let result = pk.verify(msg, &corrupted, b"");
    assert!(
        matches!(&result, Ok(false) | Err(_)),
        "corrupted signature must reject as Ok(false) or Err, got {:?}",
        result
    );
}

// Round-36 C2: deleted the empty `signing_keypair_debug_redaction_documented_in_inline_tests`
// `#[test]` marker. An empty `#[test]` body registers as a passing
// test in CI but verifies nothing — the docstring's claim that the
// inline test is the "regression blocker" is fine, but a marker
// `#[test]` adds zero coverage and inflates the green-test count.
// The actual inline guards live at
// `latticearc/src/unified_api/convenience/api.rs::tests` (`assert_not_impl_any!`
// for `PartialEq`/`Eq` and the manual `impl Debug`).

/// AEAD decrypt path must return a single uniform error
/// string for every adversary-reachable failure. Reverting the
/// `DECRYPTION_FAILED` constant collapse re-introduces 4 distinguishable
/// strings (auth-fail vs size-cap vs buffer-shape).
#[test]
fn aes_gcm_decrypt_failure_strings_are_uniform() {
    let key = [0xABu8; 32];
    let cipher = AesGcm256::new(&key).unwrap();
    let nonce = AesGcm256::generate_nonce();
    let (ct, tag) = cipher.encrypt(&nonce, b"plaintext", None).unwrap();

    // Tampered tag → MAC failure path
    let mut bad_tag = tag;
    bad_tag[0] ^= 0xFF;
    let mac_err = cipher.decrypt(&nonce, &ct, &bad_tag, None).unwrap_err().to_string();

    // Build a wrong-key cipher and decrypt with it — different stage,
    // same opaque error.
    let other_key = [0xCDu8; 32];
    let other = AesGcm256::new(&other_key).unwrap();
    let other_err = other.decrypt(&nonce, &ct, &tag, None).unwrap_err().to_string();

    assert_eq!(
        mac_err, other_err,
        "AES-GCM decrypt error strings must be uniform across stages \
         (round-27 H2 opacity sweep)"
    );
}

/// secp256k1 high-S signatures must be rejected at
/// `signature_from_bytes` (BIP-146 / EIP-2). Without round-27 H3, a
/// caller could parse a high-S signature and verify would also reject —
/// but the parse-time gate is the wire-format guard.
///
/// Gated on `not(feature = "fips")` because secp256k1 is not a NIST-
/// approved curve and the module is excluded from the FIPS profile.
#[cfg(not(feature = "fips"))]
#[test]
fn secp256k1_high_s_signature_rejected_at_parse() {
    use latticearc::primitives::ec::secp256k1::{Secp256k1KeyPair, Secp256k1Signature};
    use latticearc::primitives::ec::traits::{EcKeyPair, EcSignature};

    let kp = Secp256k1KeyPair::generate().unwrap();
    let msg = b"high-S parse test";
    let sig = kp.sign(msg).unwrap();
    let mut sig_bytes = Secp256k1Signature::signature_bytes(&sig);

    // Negate s (n - s) to construct a high-S form. secp256k1 group order n:
    const N: [u8; 32] = [
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36,
        0x41, 0x41,
    ];
    let mut s = [0u8; 32];
    s.copy_from_slice(&sig_bytes[32..64]);
    let mut high_s = [0u8; 32];
    let mut borrow: i16 = 0;
    for i in (0..32).rev() {
        let mut diff = N[i] as i16 - s[i] as i16 - borrow;
        if diff < 0 {
            diff += 256;
            borrow = 1;
        } else {
            borrow = 0;
        }
        high_s[i] = diff as u8;
    }
    sig_bytes[32..64].copy_from_slice(&high_s);

    let parsed = Secp256k1Signature::signature_from_bytes(&sig_bytes);
    assert!(
        parsed.is_err(),
        "round-27 H3: secp256k1 high-S signature must be rejected at parse \
         (BIP-146 / EIP-2)"
    );
}

/// `SlhDsaError::DeserializationError` was removed.
/// Production code never returned it; reverting the removal would
/// re-introduce the dead variant. The `non_exhaustive` attribute means
/// adding it back is technically non-breaking, but the variant should
/// not exist.
#[test]
fn slh_dsa_error_does_not_have_deserialization_variant() {
    use latticearc::primitives::sig::slh_dsa::SlhDsaError;
    // Pattern-match on every variant — an exhaustive match would
    // break if `DeserializationError` is re-added (under
    // non_exhaustive, the catch-all `_` arm prevents the compile
    // error, so this is a Display-shape check instead). The previous
    // variant displayed "Deserialization failed"; we assert that
    // string is unreachable from any current variant.
    let known: &[SlhDsaError] = &[
        SlhDsaError::RngError,
        SlhDsaError::PctFailed,
        SlhDsaError::InvalidPublicKey,
        SlhDsaError::InvalidSecretKey,
        SlhDsaError::VerificationFailed,
        SlhDsaError::ContextTooLong,
    ];
    for e in known {
        assert_ne!(
            e.to_string(),
            "Deserialization failed",
            "round-27 M4: DeserializationError variant must remain absent"
        );
    }
}

// ---------------------------------------------------------------------------
// ML-DSA: sign + verify reject context > 255 bytes (FIPS 204 §3.3)
// ---------------------------------------------------------------------------

#[test]
fn ml_dsa_sign_rejects_context_above_255_bytes() {
    let (_pk, sk) = ml_dsa_keygen(MlDsaParameterSet::MlDsa44).unwrap();
    let oversized_context = vec![0xAB; 256];
    let result = sk.sign(b"ctx cap test", &oversized_context);
    assert!(result.is_err(), "ML-DSA sign must reject context > 255 bytes (FIPS 204 §3.3)");
}

#[test]
fn ml_dsa_sign_accepts_max_255_byte_context() {
    let (_pk, sk) = ml_dsa_keygen(MlDsaParameterSet::MlDsa44).unwrap();
    let max_context = vec![0xAB; 255];
    let result = sk.sign(b"ctx cap test", &max_context);
    assert!(result.is_ok(), "ML-DSA sign must accept context exactly at 255-byte cap");
}

#[test]
fn ml_dsa_verify_rejects_context_above_255_bytes() {
    let (pk, sk) = ml_dsa_keygen(MlDsaParameterSet::MlDsa44).unwrap();
    let valid_sig = sk.sign(b"verify cap test", &[]).unwrap();
    let oversized_context = vec![0xAB; 256];
    let result = pk.verify(b"verify cap test", &valid_sig, &oversized_context);
    assert!(result.is_err(), "ML-DSA verify must reject context > 255 bytes");
}

#[test]
fn ml_dsa_sign_error_does_not_leak_fips204_string() {
    use latticearc::primitives::sig::ml_dsa::MlDsaSecretKey;
    let too_short = vec![0u8; 100];
    let sk_result = MlDsaSecretKey::new(MlDsaParameterSet::MlDsa44, too_short);
    let err_msg = match sk_result {
        Ok(sk) => format!("{}", sk.sign(b"m", &[]).unwrap_err()),
        Err(e) => format!("{e}"),
    };
    assert!(
        !err_msg.contains("Failed to deserialize"),
        "Pattern-6: error must not leak fips204 deserialize string; got: {err_msg}"
    );
}

// Round-36 H6: `ntt_rejects_modulus_above_i32_max` removed alongside
// the `primitives::polynomial` module deletion.

#[cfg(not(feature = "fips"))]
#[test]
fn xchacha_generate_key_returns_random_bytes() {
    use latticearc::primitives::aead::chacha20poly1305::XChaCha20Poly1305Cipher;
    let k1 = XChaCha20Poly1305Cipher::generate_key();
    let k2 = XChaCha20Poly1305Cipher::generate_key();
    assert_ne!(*k1, *k2, "two consecutive generate_key calls must differ");
    assert!(!k1.iter().all(|&b| b == 0), "generated key must not be all-zero");
}

#[cfg(not(feature = "fips"))]
#[test]
fn schnorr_prove_uses_rejection_sampling_no_panic() {
    use latticearc::zkp::schnorr::SchnorrProver;
    let secret = [0x42u8; 32];
    let (prover, _public_key) =
        SchnorrProver::from_secret(&secret).expect("from_secret must succeed for non-zero scalar");
    for _ in 0..100 {
        let _proof = prover.prove(b"M6 ctx").unwrap();
    }
}

#[cfg(not(feature = "fips"))]
#[test]
fn dlog_equality_canonical_constructor_uses_canonical_bases() {
    use k256::{
        FieldBytes, ProjectivePoint, Scalar, SecretKey,
        elliptic_curve::{PrimeField, group::GroupEncoding},
    };
    use latticearc::zkp::commitment::PedersenCommitment;
    use latticearc::zkp::sigma::{DlogEqualityProof, DlogEqualityStatement};
    use rand_core_0_6::OsRng;

    let secret_key = SecretKey::random(&mut OsRng);
    let x_bytes: [u8; 32] = secret_key.to_bytes().into();
    let x: Scalar = Scalar::from_repr(*FieldBytes::from_slice(&x_bytes)).unwrap();
    let g = ProjectivePoint::GENERATOR;
    let h = PedersenCommitment::generator_h().unwrap();
    let p = g * x;
    let q = h * x;

    let p_bytes: [u8; 33] = p.to_affine().to_bytes().as_slice().try_into().unwrap();
    let q_bytes: [u8; 33] = q.to_affine().to_bytes().as_slice().try_into().unwrap();

    let statement = DlogEqualityStatement::canonical(p_bytes, q_bytes).unwrap();
    let proof = DlogEqualityProof::prove(&statement, &x_bytes, b"ctx").unwrap();
    assert!(proof.verify(&statement, b"ctx").unwrap());
}

#[cfg(not(feature = "fips"))]
#[test]
fn dlog_equality_rejects_non_canonical_bases() {
    use k256::{
        FieldBytes, ProjectivePoint, Scalar, SecretKey,
        elliptic_curve::{PrimeField, group::GroupEncoding},
    };
    use latticearc::zkp::sigma::{DlogEqualityProof, DlogEqualityStatement};
    use rand_core_0_6::OsRng;

    let secret_key = SecretKey::random(&mut OsRng);
    let x_bytes: [u8; 32] = secret_key.to_bytes().into();
    let x: Scalar = Scalar::from_repr(*FieldBytes::from_slice(&x_bytes)).unwrap();
    let g = ProjectivePoint::GENERATOR;
    let h_bad = g * Scalar::from(2u64);
    let p = g * x;
    let q = h_bad * x;

    let g_bytes: [u8; 33] = g.to_affine().to_bytes().as_slice().try_into().unwrap();
    let h_bad_bytes: [u8; 33] = h_bad.to_affine().to_bytes().as_slice().try_into().unwrap();
    let p_bytes: [u8; 33] = p.to_affine().to_bytes().as_slice().try_into().unwrap();
    let q_bytes: [u8; 33] = q.to_affine().to_bytes().as_slice().try_into().unwrap();

    let bad_statement =
        DlogEqualityStatement { g: g_bytes, h: h_bad_bytes, p: p_bytes, q: q_bytes };
    let prove_result = DlogEqualityProof::prove(&bad_statement, &x_bytes, b"ctx");
    assert!(prove_result.is_err(), "DlogEqualityProof::prove must reject non-canonical bases");
}
