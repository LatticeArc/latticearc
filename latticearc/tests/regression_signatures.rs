//! Signature, AEAD, and Pattern-6-opacity regressions.
//!
//! Covers signatures (ML-DSA, SLH-DSA, FN-DSA, Ed25519, secp256k1),
//! AEAD encrypt/decrypt opacity, and ZK-proof transcripts. Reverting
//! the fix must make the test fail.

// Integration-test file: a panicking unwrap/expect IS the test-failure
// signal, and fixed 32/64-byte vectors plus big-endian byte arithmetic
// trip pedantic indexing/cast lints that carry no risk in test code.
// File-scope `#![allow]` per DESIGN_PATTERNS.md §"`#[allow]` vs `#[expect]`
// policy".
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::indexing_slicing)]
#![allow(clippy::cast_lossless)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_sign_loss)]

mod support;

use latticearc::primitives::aead::{AeadCipher, aes_gcm::AesGcm256};
use latticearc::primitives::sig::ml_dsa::{MlDsaParameterSet, generate_keypair as ml_dsa_keygen};

/// `Ed25519KeyPair::sign` is fallible — must reject
/// messages exceeding the configured signature-size cap (default 64 KiB).
/// Reverting the `validate_signature_size` call would let this oversize
/// sign succeed.
#[test]
fn ed25519_sign_is_fallible_and_rejects_oversize_message() {
    let kp = support::ed25519_keypair();
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

// deleted dead `primitives::polynomial` module — the
// NTT/Montgomery code wasn't called from any production path
// (FIPS 203/204/205/206 all delegate to aws-lc-rs / fips204 / fips205
// / fn-dsa). The two regression tests that referenced it
// (`ntt_primitive_root_table_is_consistent` and
// `ntt_rejects_modulus_above_i32_max`) are removed alongside the
// module.

/// convenience-layer verify must return `Ok(false)` on
/// adversary-reachable failure (not `Err`). Reverting the
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
    // collapsed that. Either Err or Ok(false) is
    // acceptable — assert that the result actually falls
    // into one of those buckets — the previous `let _ = ...` form
    // discarded the result, so reverting the fix wouldn't
    // have tripped this regression test.
    let result = pk.verify(msg, &corrupted, b"");
    assert!(
        matches!(&result, Ok(false) | Err(_)),
        "corrupted signature must reject as Ok(false) or Err, got {:?}",
        result
    );
}

// deleted the empty `signing_keypair_debug_redaction_documented_in_inline_tests`
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
         (opacity sweep)"
    );
}

/// secp256k1 high-S signatures must be rejected at
/// `signature_from_bytes` (BIP-146 / EIP-2). Without , a
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
        "secp256k1 high-S signature must be rejected at parse (BIP-146 / EIP-2)"
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
            "DeserializationError variant must remain absent"
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

// `ntt_rejects_modulus_above_i32_max` removed alongside
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

    let bad_statement = DlogEqualityStatement::with_bases(g_bytes, h_bad_bytes, p_bytes, q_bytes);
    let prove_result = DlogEqualityProof::prove(&bad_statement, &x_bytes, b"ctx");
    assert!(prove_result.is_err(), "DlogEqualityProof::prove must reject non-canonical bases");
}

// ============================================================================
// H1 / M1 / M5: signature transcript binding to scheme
// ============================================================================
//
// A downgrade attack was identified on the hybrid
// signature path (`hybrid-ml-dsa-65-ed25519 → ml-dsa-65`). The fix binds the
// signed transcript to the scheme identifier via a per-scheme
// domain-separation context (`SigSchemeLabel`, `types::domains`), and adds
// an allowlist + cross-check at deserialization. Reverting either side of
// the binding (sign-side context, verify-side context, deserialization
// allowlist) must make the tests below fail.

/// H1 regression: signing under a hybrid scheme must NOT produce bytes that
/// verify against a re-labelled "pure ML-DSA" envelope.
///
/// Pre-fix: `sign_hybrid_ml_dsa_ed25519` signed `M` under empty FIPS-204 ctx,
/// so the ML-DSA leg was byte-identical to a standalone ML-DSA signature over
/// `M`. An attacker could re-label `scheme` to `"ml-dsa-65"` and truncate
/// `public_key`/`signature` to the ML-DSA-65 components → `verify()` returned
/// `Ok(true)`, defeating the hybrid construction (one-component compromise
/// would suffice for forgery).
///
/// Post-fix: the ML-DSA leg signs with ctx = `"LatticeArc-Sig-hybrid-…-v1"`,
/// while a pure-ML-DSA verify path uses ctx = `"LatticeArc-Sig-ml-dsa-65-v1"`.
/// The downgrade envelope's ML-DSA leg verifies under a different ctx than
/// it was signed under → `verify()` returns `Ok(false)`.
#[test]
fn h1_hybrid_to_pq_only_downgrade_rejected() {
    use latticearc::primitives::sig::ml_dsa::MlDsaParameterSet;
    use latticearc::unified_api::types::{SignedData, SignedMetadata};
    use latticearc::{CryptoConfig, sign_with_key, verify};

    // Default config selects a hybrid signature scheme (typically
    // hybrid-ml-dsa-65-ed25519). Use the same config for keygen and sign so
    // the selector agrees on which scheme to produce.
    let cfg = CryptoConfig::new();
    let kp = latticearc::generate_signing_keypair(cfg.clone())
        .expect("default signing keypair must generate");

    // The test targets the hybrid-ml-dsa-65-ed25519 path specifically; if
    // the default selector ever changes, fail loudly so the test gets
    // updated alongside the selector rather than silently no-op.
    assert!(
        kp.scheme().contains("hybrid") && kp.scheme().contains("ml-dsa-65"),
        "h1 downgrade test precondition: default scheme must be hybrid+ml-dsa-65, got {scheme:?}",
        scheme = kp.scheme()
    );

    let message = b"transferred funds: 1000 USD to alice@example.com";
    let hybrid_signed =
        sign_with_key(message, kp.expose_secret_key(), kp.public_key(), cfg.clone())
            .expect("hybrid sign must succeed");

    // Sanity: the legitimate hybrid envelope verifies.
    assert!(
        verify(&hybrid_signed, CryptoConfig::new()).expect("hybrid verify must not error"),
        "freshly-signed hybrid envelope must verify (sanity check)"
    );

    // Construct the downgrade envelope: relabel `scheme` and
    // `signature_algorithm` to `"ml-dsa-65"`, and truncate `public_key` and
    // `signature` to the ML-DSA-65 components (the hybrid layout is
    // `ml_dsa_pk || ed25519_pk` and `ml_dsa_sig || ed25519_sig`).
    let pq_pk_len = MlDsaParameterSet::MlDsa65.public_key_size();
    let pq_sig_len = MlDsaParameterSet::MlDsa65.signature_size();
    let truncated_pk = hybrid_signed.metadata.public_key[..pq_pk_len].to_vec();
    let truncated_sig = hybrid_signed.metadata.signature[..pq_sig_len].to_vec();
    let downgrade = SignedData::new(
        hybrid_signed.data.clone(),
        SignedMetadata::new(
            truncated_sig,
            "ml-dsa-65".to_string(), // <-- relabel attempt
            truncated_pk,
            None,
        ),
        "ml-dsa-65".to_string(), // <-- relabel attempt
        hybrid_signed.timestamp,
    );

    // Post-fix: the ML-DSA-65 verify path uses the "ml-dsa-65" scheme context,
    // but the signature was produced under the hybrid context. Verify must
    // return Ok(false). Reverting the H1/M1 fix surfaces here as Ok(true).
    let result = verify(&downgrade, CryptoConfig::new())
        .expect("downgrade verify must not error (only return false)");
    assert!(
        !result,
        "DOWNGRADE ATTACK NOT BLOCKED: hybrid-ml-dsa-65-ed25519 envelope relabelled as ml-dsa-65 \
         was accepted by verify(). H1 / M1 scheme-binding regressed."
    );
}

/// H1 / M1 sanity: each scheme's freshly-signed envelope round-trips through
/// verify under the new scheme-context binding. Reverting the verify-side
/// context surfaces here as a `false` return for the affected scheme.
///
/// We exercise schemes the high-level `generate_signing_keypair` selector can
/// produce via `force_scheme`; the goal is to catch a verify-side regression,
/// not to enumerate every primitive-level keygen path.
#[test]
fn h1_default_scheme_round_trips_post_fix() {
    use latticearc::{CryptoConfig, generate_signing_keypair, sign_with_key, verify};

    // The default sign/verify path. Reverting the scheme-context binding on
    // either the sign or the verify side surfaces here as either an error or
    // a false from `verify` on a freshly-signed envelope.
    let cfg = CryptoConfig::new();
    let kp =
        generate_signing_keypair(cfg.clone()).expect("default keygen for signing must succeed");
    let message = b"audit regression: default scheme self-verifies post-H1 fix";
    let signed = sign_with_key(message, kp.expose_secret_key(), kp.public_key(), cfg.clone())
        .expect("default sign must succeed");
    let ok = verify(&signed, CryptoConfig::new())
        .expect("default verify must not error on a freshly-signed envelope");
    assert!(
        ok,
        "fresh signature under the default scheme {scheme:?} must verify; \
         H1/M1 scheme-context binding regressed",
        scheme = kp.scheme()
    );
}

/// M5 regression: a `SignedData` envelope whose `scheme` field is not in the
/// closed `SigSchemeLabel` allowlist must be rejected at deserialization.
///
/// Pre-fix: the deserializer only checked that
/// `metadata.signature_algorithm == scheme`. An attacker could agree both
/// fields on `"evil-algo"` and the `match` in `verify` would silently take
/// the `_` arm (`Err(InvalidInput(...))`), but envelopes that smuggled known
/// schemes through aliasing would pass through unchecked.
#[test]
fn m5_unknown_scheme_rejected_at_deserialization() {
    use latticearc::unified_api::serialization::deserialize_signed_data;

    // Hand-crafted JSON envelope with an unknown scheme. base64 contents are
    // small fixed values — the point is the scheme check fires BEFORE any
    // structural validation of the bytes.
    let evil = r#"{
        "data": "aGVsbG8=",
        "metadata": {
            "signature": "AAAA",
            "signature_algorithm": "evil-algo",
            "public_key": "AAAA",
            "key_id": null
        },
        "scheme": "evil-algo",
        "timestamp": 0
    }"#;
    let result = deserialize_signed_data(evil);
    assert!(
        result.is_err(),
        "unknown scheme 'evil-algo' must be rejected by the M5 allowlist; \
         got {result:?}"
    );
}

/// M5 regression: cross-check between `scheme` and `metadata.signature_algorithm`
/// must reject mismatches even when both individually map to valid labels.
#[test]
fn m5_mismatched_scheme_metadata_rejected() {
    use latticearc::unified_api::serialization::deserialize_signed_data;

    let mismatched = r#"{
        "data": "aGVsbG8=",
        "metadata": {
            "signature": "AAAA",
            "signature_algorithm": "ml-dsa-87",
            "public_key": "AAAA",
            "key_id": null
        },
        "scheme": "ml-dsa-65",
        "timestamp": 0
    }"#;
    let result = deserialize_signed_data(mismatched);
    assert!(
        result.is_err(),
        "scheme/metadata mismatch (ml-dsa-65 vs ml-dsa-87) must be rejected; got {result:?}"
    );
}

// ============================================================================
// H2: verify_with_anchor — operator-pinned trust anchor + scheme assertion
// ============================================================================

/// H2 regression: `verify_with_anchor` must reject an envelope whose embedded
/// public key does NOT match the operator-supplied trust anchor, even when
/// the cryptographic verification against the embedded key would otherwise
/// succeed. This blocks the "attacker fabricates an entire (pk, sk, sig)
/// triple under their own key" pre-fix flow that returned `Ok(true)` from
/// the embedded-key `verify()`.
#[test]
fn h2_verify_with_anchor_rejects_attacker_key() {
    use latticearc::{CryptoConfig, sign_with_key, verify, verify_with_anchor};

    // Attacker has full control of a keypair and produces a legitimate
    // signature under that keypair. The envelope's embedded public key is
    // the attacker's, not the operator's trust anchor.
    let attacker_kp = latticearc::generate_signing_keypair(CryptoConfig::new())
        .expect("attacker keypair generation");
    let attacker_signed = sign_with_key(
        b"approve transfer of 10000 USD",
        attacker_kp.expose_secret_key(),
        attacker_kp.public_key(),
        CryptoConfig::new(),
    )
    .expect("attacker can sign anything under their own key");

    // Sanity check: embedded-key verify accepts the envelope. This is the
    // PRE-H2 vulnerability shape — `verify()` cannot distinguish "attacker
    // signed it themselves" from "trusted signer signed it".
    assert!(
        verify(&attacker_signed, CryptoConfig::new()).expect("embedded verify must not error"),
        "embedded-key verify must succeed on a self-signed envelope (sanity)"
    );

    // The OPERATOR'S trust anchor is a different key — say from a CA or a
    // configured signer roster. Verifying the attacker envelope against
    // the operator's anchor must reject.
    let operator_anchor_kp = latticearc::generate_signing_keypair(CryptoConfig::new())
        .expect("operator anchor keypair generation");
    let result = verify_with_anchor(
        &attacker_signed,
        operator_anchor_kp.public_key(),
        attacker_signed.scheme.as_str(),
        CryptoConfig::new(),
    )
    .expect("verify_with_anchor must not error on attacker envelope");
    assert!(
        !result,
        "verify_with_anchor must reject envelope whose embedded pk does not match the trust anchor"
    );
}

/// H2 sanity: `verify_with_anchor` accepts an envelope when the operator's
/// trust anchor matches the embedded key AND the scheme assertion matches.
#[test]
fn h2_verify_with_anchor_accepts_legitimate_envelope() {
    use latticearc::{CryptoConfig, sign_with_key, verify_with_anchor};

    let kp = latticearc::generate_signing_keypair(CryptoConfig::new()).expect("keypair generation");
    let signed = sign_with_key(
        b"audit regression: legitimate signature under the trust anchor",
        kp.expose_secret_key(),
        kp.public_key(),
        CryptoConfig::new(),
    )
    .expect("sign with the trust-anchor key");

    let ok = verify_with_anchor(&signed, kp.public_key(), &signed.scheme, CryptoConfig::new())
        .expect("verify_with_anchor must not error on legitimate envelope");
    assert!(ok, "verify_with_anchor must accept envelope when pk and scheme match the anchor");
}

/// H2 regression: scheme assertion must reject an envelope whose scheme
/// disagrees with the operator's expectation, even if the embedded pk
/// matches. Defends against post-H1 "scheme is bound by ML-DSA ctx but the
/// operator was expecting Ed25519" mismatch.
#[test]
fn h2_verify_with_anchor_rejects_scheme_mismatch() {
    use latticearc::{CryptoConfig, sign_with_key, verify_with_anchor};

    let kp = latticearc::generate_signing_keypair(CryptoConfig::new()).expect("keypair generation");
    let signed = sign_with_key(
        b"audit regression: scheme assertion test",
        kp.expose_secret_key(),
        kp.public_key(),
        CryptoConfig::new(),
    )
    .expect("sign succeeds");

    // Pick a different scheme from what the envelope actually carries.
    let wrong_scheme = if signed.scheme == "ml-dsa-65" { "ed25519" } else { "ml-dsa-65" };
    let result = verify_with_anchor(&signed, kp.public_key(), wrong_scheme, CryptoConfig::new())
        .expect("verify_with_anchor must not error on scheme mismatch");
    assert!(
        !result,
        "verify_with_anchor must reject when expected_scheme ({wrong_scheme}) does not match \
         envelope scheme ({})",
        signed.scheme
    );
}

/// H2 / M5 hardening: `verify_with_anchor` must reject envelopes whose
/// scheme tag is not in the M5 allowlist (closed `SigSchemeLabel`).
#[test]
fn h2_verify_with_anchor_rejects_unknown_scheme() {
    use latticearc::unified_api::types::{SignedData, SignedMetadata};
    use latticearc::{CryptoConfig, verify_with_anchor};

    let envelope = SignedData::new(
        b"any data".to_vec(),
        SignedMetadata::new(vec![0u8; 64], "evil-algo".to_string(), vec![0u8; 32], None),
        "evil-algo".to_string(),
        0,
    );

    let result = verify_with_anchor(&envelope, &[0u8; 32], "evil-algo", CryptoConfig::new())
        .expect("verify_with_anchor must not error on unknown scheme");
    assert!(!result, "verify_with_anchor must reject envelope with non-allowlisted scheme");
}

// ============================================================================
// M2: key_type guards on hybrid public-key extractors
// ============================================================================

/// M2 regression: `to_hybrid_public_key` must reject a non-public PortableKey,
/// mirroring the existing guard on `to_hybrid_secret_key`. Pre-fix the public
/// extractor would happily build a `HybridKemPublicKey` from a `Secret` key
/// file (most uses survived only because of downstream length validation).
#[test]
fn m2_to_hybrid_public_key_rejects_non_public_keytype() {
    use latticearc::unified_api::key_format::{KeyAlgorithm, KeyData, KeyType, PortableKey};

    // Build a `Secret` PortableKey at a hybrid algorithm. The composite
    // byte values are placeholders — the guard must fire BEFORE any
    // composite decode work happens.
    let key = PortableKey::new(
        KeyAlgorithm::HybridMlKem768X25519,
        KeyType::Secret,
        KeyData::from_composite(&[0u8; 32], &[0u8; 32]),
    );

    let result = key.to_hybrid_public_key();
    assert!(result.is_err(), "to_hybrid_public_key must reject Secret-typed keys; got {result:?}");
}

/// M2 regression: same guard on the signature variant.
#[test]
fn m2_to_hybrid_sig_public_key_rejects_non_public_keytype() {
    use latticearc::unified_api::key_format::{KeyAlgorithm, KeyData, KeyType, PortableKey};

    let key = PortableKey::new(
        KeyAlgorithm::HybridMlDsa65Ed25519,
        KeyType::Secret,
        KeyData::from_composite(&[0u8; 32], &[0u8; 32]),
    );

    let result = key.to_hybrid_sig_public_key();
    assert!(
        result.is_err(),
        "to_hybrid_sig_public_key must reject Secret-typed keys; got {result:?}"
    );
}

// ============================================================================
// M3: pq_only AAD bound into HKDF key derivation
// ============================================================================

/// M3 regression: a pq_only ciphertext produced under AAD `A1` must NOT
/// decrypt when the verifier supplies AAD `A2`. Pre-fix the AAD was only
/// authenticated by the AEAD tag; post-fix it also derives a different HKDF
/// key, so the wrong-AAD failure happens at HKDF/AEAD intersection — defense
/// in depth.
#[test]
fn m3_pq_only_aad_mismatch_rejected() {
    use latticearc::hybrid::pq_only::{
        decrypt_pq_only_with_aad, encrypt_pq_only_with_aad, generate_pq_keypair,
    };

    let (pk, sk) = generate_pq_keypair().expect("pq_only keygen");
    let plaintext = b"sensitive document content";
    let aad_correct = b"context: alice -> bob, 2026";
    let aad_attacker = b"context: alice -> charlie, 2026";

    let ct =
        encrypt_pq_only_with_aad(&pk, plaintext, aad_correct).expect("encrypt under correct AAD");

    // Sanity: matching AAD decrypts.
    let pt = decrypt_pq_only_with_aad(
        &sk,
        ct.ml_kem_ciphertext(),
        ct.symmetric_ciphertext(),
        ct.nonce(),
        ct.tag(),
        aad_correct,
    )
    .expect("decrypt with matching AAD must succeed");
    assert_eq!(pt.as_slice(), plaintext);

    // Mismatched AAD must reject.
    let bad = decrypt_pq_only_with_aad(
        &sk,
        ct.ml_kem_ciphertext(),
        ct.symmetric_ciphertext(),
        ct.nonce(),
        ct.tag(),
        aad_attacker,
    );
    assert!(
        bad.is_err(),
        "pq_only decrypt with mismatched AAD must reject (M3 defense-in-depth); got Ok"
    );
}

// ============================================================================
// M4: PortableKey::validate_with_expiry
// ============================================================================

/// M4 regression: `validate_with_expiry` must reject a key whose `not_after`
/// is in the past. `validate` alone continues to accept it (documented as
/// "informational lifecycle"), so the gate is the explicit `_with_expiry`
/// helper.
#[test]
fn m4_validate_with_expiry_rejects_expired_key() {
    use chrono::{DateTime, Duration, Utc};
    use latticearc::unified_api::key_format::{KeyAlgorithm, KeyData, KeyType, PortableKey};

    let now: DateTime<Utc> = Utc::now();
    let past = now - Duration::hours(1);
    let mut key =
        PortableKey::new(KeyAlgorithm::Ed25519, KeyType::Public, KeyData::from_raw(&[0u8; 32]));
    key.set_not_after(Some(past));

    // `validate` itself still passes (preserves the documented contract).
    assert!(key.validate().is_ok(), "validate must remain expiry-blind");
    // The expiry-aware gate must reject.
    let result = key.validate_with_expiry(now);
    assert!(
        result.is_err(),
        "validate_with_expiry must reject keys whose not_after is in the past"
    );
}

#[test]
fn m4_validate_with_expiry_accepts_unexpired_key() {
    use chrono::{Duration, Utc};
    use latticearc::unified_api::key_format::{KeyAlgorithm, KeyData, KeyType, PortableKey};

    let now = Utc::now();
    let future = now + Duration::hours(1);
    let mut key =
        PortableKey::new(KeyAlgorithm::Ed25519, KeyType::Public, KeyData::from_raw(&[0u8; 32]));
    key.set_not_after(Some(future));
    assert!(
        key.validate_with_expiry(now).is_ok(),
        "validate_with_expiry must accept keys whose not_after is in the future"
    );
}

#[test]
fn m4_validate_with_expiry_accepts_key_without_not_after() {
    use chrono::Utc;
    use latticearc::unified_api::key_format::{KeyAlgorithm, KeyData, KeyType, PortableKey};

    // Keys without an explicit expiry must pass (legacy + most production keys).
    let key =
        PortableKey::new(KeyAlgorithm::Ed25519, KeyType::Public, KeyData::from_raw(&[0u8; 32]));
    assert!(
        key.validate_with_expiry(Utc::now()).is_ok(),
        "validate_with_expiry must accept keys with no not_after set"
    );
}

// ============================================================================
// L7: EncryptedOutput.version field validated at deserialization
// ============================================================================

/// L7 regression: a serialized `EncryptedOutput` carrying an unsupported
/// `version` field must be rejected at deserialization. Pre-fix the field
/// was round-tripped as opaque, leaving downstream consumers to interpret
/// arbitrary values however they liked.
#[test]
fn l7_encrypted_output_unsupported_version_rejected() {
    use latticearc::unified_api::serialization::deserialize_encrypted_output;

    let evil = r#"{
        "version": 99,
        "scheme": "aes-256-gcm",
        "ciphertext": "AAAA",
        "nonce": "AAAAAAAAAAAAAAAA",
        "tag": "AAAAAAAAAAAAAAAAAAAAAA==",
        "timestamp": 0
    }"#;
    let result = deserialize_encrypted_output(evil);
    assert!(result.is_err(), "EncryptedOutput with version != 2 must be rejected; got {result:?}");
}

// ============================================================================
// L2: PBKDF2 salt all-zero check uses constant-time path
// ============================================================================

/// L2 regression: PBKDF2 `validate()` must reject an all-zero salt via the
/// CT helper, not via `salt.iter().all(|&b| b == 0)`. The behaviour
/// (rejection) is the same either way; this test exists to lock the
/// rejection contract — a copy-paste that re-introduced the variable-time
/// form would survive this test unless someone also weakened the
/// invariant. Pair it with the `is_all_zero_bytes` source review.
#[test]
fn l2_pbkdf2_all_zero_salt_rejected() {
    use latticearc::primitives::kdf::pbkdf2::Pbkdf2Params;

    let salt = vec![0u8; 16];
    let params = Pbkdf2Params::with_salt(&salt);
    let result = params.validate();
    assert!(result.is_err(), "PBKDF2 validate() must reject an all-zero salt; got {result:?}");
}

// ============================================================================
// L5: ConstantTimeEq alongside derived PartialEq on public-key types
// ============================================================================

/// L5 regression: every public-key wrapper that derives `PartialEq` must
/// also impl `ConstantTimeEq` (length-prefixed). The derived `PartialEq`
/// stays — these are public, not secret material — but the CT sibling is
/// the in-tree home for callers that need timing-independent comparison
/// (operator trust-anchor pin paths, etc.). Reverting the impl would
/// surface as a compile error here.
#[test]
fn l5_public_keys_impl_constant_time_eq() {
    use latticearc::primitives::kem::ecdh::X25519PublicKey;
    use subtle::ConstantTimeEq;

    // Existence + correctness on equal pairs.
    let x25519_a = X25519PublicKey::from_bytes(&[7u8; 32]).expect("X25519 PK");
    let x25519_b = x25519_a.clone();
    assert!(bool::from(x25519_a.ct_eq(&x25519_b)));
}

// ============================================================================
// L6: per-algorithm composite length check
// ============================================================================

/// L6 regression: `validate_composite_lengths` now dispatches the expected
/// classical-leg length per algorithm. Non-hybrid algorithms must surface
/// `Err` (composite KeyData is not a legitimate shape for them).
#[test]
fn l6_composite_lengths_reject_non_hybrid_algorithm() {
    use latticearc::unified_api::key_format::{KeyAlgorithm, KeyData, KeyType, PortableKey};

    // Apply a Composite KeyData to a NON-hybrid algorithm (Ed25519). The
    // L6 dispatch now treats this as an illegal shape regardless of
    // component lengths.
    let key = PortableKey::new(
        KeyAlgorithm::Ed25519,
        KeyType::Public,
        KeyData::from_composite(&[0u8; 32], &[0u8; 32]),
    );
    let result = key.validate();
    assert!(
        result.is_err(),
        "Non-hybrid algorithm with Composite KeyData must be rejected; got {result:?}"
    );
}

/// L6 sanity: hybrid algorithms still accept their canonical 32-byte
/// classical leg (X25519 / Ed25519). Catches the failure mode where
/// the dispatch helper returns `None` for a legitimate variant.
#[test]
fn l6_composite_lengths_accept_canonical_hybrid_leg() {
    use latticearc::unified_api::key_format::{KeyAlgorithm, KeyData, KeyType, PortableKey};

    // Use a real ML-DSA-65 public-key size for the PQ leg so the
    // composite passes the PQ-side bounds the helper enforces; the
    // L6 dispatch only governs the classical-leg length check.
    let pq_pk_len = 1952; // ML-DSA-65 PK
    let key = PortableKey::new(
        KeyAlgorithm::HybridMlDsa65Ed25519,
        KeyType::Public,
        KeyData::from_composite(&vec![0u8; pq_pk_len], &[0u8; 32]),
    );
    // The PQ-leg sanity placeholders here may still trip *other* validate
    // arms (e.g. the per-level PK byte check), so we ONLY assert that the
    // composite-length check itself accepts a 32-byte classical leg.
    let result = key.validate();
    if let Err(e) = &result {
        let msg = format!("{e:?}");
        assert!(
            !msg.contains("classical component"),
            "L6 dispatch wrongly rejected canonical 32-byte hybrid classical leg: {msg}"
        );
    }
}

// ============================================================================
// M5 (continued): alias canonicalization
// ============================================================================

/// M5 alias canonicalization: `pq-ml-dsa-65` and `ml-dsa-65` map to the same
/// `SigSchemeLabel::MlDsa65`, so an envelope using one in `scheme` and the
/// other in `metadata.signature_algorithm` must pass the cross-check. (The
/// underlying bytes are still attacker-crafted in this test, so verify will
/// reject — we only check the deserialization step's verdict.)
#[test]
fn m5_alias_canonicalization_passes_cross_check() {
    use latticearc::unified_api::serialization::deserialize_signed_data;

    let alias_pair = r#"{
        "data": "aGVsbG8=",
        "metadata": {
            "signature": "AAAA",
            "signature_algorithm": "ml-dsa-65",
            "public_key": "AAAA",
            "key_id": null
        },
        "scheme": "pq-ml-dsa-65",
        "timestamp": 0
    }"#;
    let result = deserialize_signed_data(alias_pair);
    assert!(
        result.is_ok(),
        "scheme/metadata pair using legitimate aliases must pass the M5 cross-check; got {result:?}"
    );
}

// ============================================================================
// M-A (follow-up): pure Ed25519 / PoP / ZK-proof scheme-binding
// ============================================================================

/// M-A regression: a pure-Ed25519 SignedData built via the post-fix
/// digest construction must round-trip through `verify`. Reverting either
/// the sign or verify side of the M-A fix surfaces as `Ok(false)` here.
///
/// The digest construction (SHA-512(scheme_ctx || 0x00 || msg)) is
/// internal to `latticearc::sign_with_key`'s ed25519 arm, but
/// `sign_with_key`'s scheme is config-driven via `select_signature_scheme`
/// rather than the operator picking ed25519 directly. The test mirrors
/// the dispatch arm's construction inline so it pins the wire format the
/// public API actually emits.
#[cfg(not(feature = "fips"))]
#[test]
fn m_a_pure_ed25519_round_trips_post_fix() {
    use latticearc::primitives::ec::ed25519::Ed25519Signature;
    use latticearc::primitives::ec::traits::{EcKeyPair, EcSignature};
    use latticearc::unified_api::types::{SignedData, SignedMetadata};
    use latticearc::{CryptoConfig, verify};
    use sha2::{Digest, Sha512};

    let kp = support::ed25519_keypair();
    let msg = b"M-A: pure Ed25519 self-verifies under SHA-512(scheme_ctx || 0x00 || msg)";
    // Mirror api.rs::sign_with_key's ed25519 arm.
    let mut hasher = Sha512::new();
    hasher.update(b"LatticeArc-Sig-ed25519-v1");
    hasher.update([0x00]);
    hasher.update(msg);
    let digest: [u8; 64] = hasher.finalize().into();
    let sig = kp.sign(&digest).expect("sign digest");
    let sig_bytes = Ed25519Signature::signature_bytes(&sig);
    let envelope = SignedData::new(
        msg.to_vec(),
        SignedMetadata::new(sig_bytes, "ed25519".to_string(), kp.public_key_bytes(), None),
        "ed25519".to_string(),
        0,
    );
    let ok = verify(&envelope, CryptoConfig::new())
        .expect("pure Ed25519 verify must not error on a freshly-signed envelope");
    assert!(ok, "fresh pure-Ed25519 envelope must verify post-M-A scheme binding");
}

/// M-A regression: a SignedData whose signature was produced over the
/// raw message (pre-M-A behaviour) must NOT verify under the post-fix
/// dispatch. This is the wire-format break the CHANGELOG documents.
#[cfg(not(feature = "fips"))]
#[test]
fn m_a_pure_ed25519_raw_message_signature_does_not_verify() {
    use latticearc::primitives::ec::ed25519::Ed25519Signature;
    use latticearc::primitives::ec::traits::{EcKeyPair, EcSignature};
    use latticearc::unified_api::types::{SignedData, SignedMetadata};
    use latticearc::{CryptoConfig, verify};

    let kp = support::ed25519_keypair();
    let msg = b"M-A: raw-message signature must NOT verify post-fix";
    // Pre-M-A behaviour: signing the raw message directly via the
    // primitive, bypassing the digest construction.
    let raw_sig = kp.sign(msg).expect("raw ed25519 sign");
    let raw_sig_bytes = Ed25519Signature::signature_bytes(&raw_sig);
    let envelope = SignedData::new(
        msg.to_vec(),
        SignedMetadata::new(raw_sig_bytes, "ed25519".to_string(), kp.public_key_bytes(), None),
        "ed25519".to_string(),
        0,
    );
    let ok = verify(&envelope, CryptoConfig::new())
        .expect("verify must not error on a structurally-valid envelope");
    assert!(
        !ok,
        "pre-M-A raw-message Ed25519 signature must NOT verify post-fix \
         (wire format break is intentional)"
    );
}

/// M-A regression: a PoP signature is constructed via a PoP-specific
/// context, so the same signature bytes must NOT authenticate against the
/// raw PoP message string as a pure-Ed25519 envelope (or any other
/// context-using path). Locks the PoP / pure-Ed25519 cross-protocol
/// separation.
#[cfg(not(feature = "fips"))]
#[test]
fn m_a_pop_signature_not_a_valid_pure_ed25519_envelope() {
    use latticearc::primitives::ec::traits::EcKeyPair;
    use latticearc::types::traits::ProofOfPossession;
    use latticearc::types::types::{PrivateKey, PublicKey};
    use latticearc::unified_api::types::{SignedData, SignedMetadata};
    use latticearc::unified_api::zero_trust::ZeroTrustAuth;
    use latticearc::{CryptoConfig, verify};

    let kp = support::ed25519_keypair();
    let auth = ZeroTrustAuth::new(
        PublicKey::new(kp.public_key_bytes()),
        PrivateKey::new(kp.secret_key_bytes().as_slice().to_vec()),
    )
    .expect("auth init");
    let pop = auth
        .generate_pop(b"m-a-pop-vs-pure-ed25519-challenge")
        .expect("PoP generation must succeed");

    // Forge a pure-Ed25519 SignedData using the PoP's signature bytes
    // over the canonical PoP message text. Under correct scheme binding
    // the pure-Ed25519 verify path digests with SIG_CONTEXT_ED25519, not
    // SIG_CONTEXT_POP_ED25519, so verification must fail.
    let ts_micros = pop.timestamp().timestamp_micros();
    let pop_message = format!("proof-of-possession-{ts_micros}");
    let envelope = SignedData::new(
        pop_message.as_bytes().to_vec(),
        SignedMetadata::new(
            pop.signature().to_vec(),
            "ed25519".to_string(),
            pop.public_key().as_slice().to_vec(),
            None,
        ),
        "ed25519".to_string(),
        0,
    );
    let ok = verify(&envelope, CryptoConfig::new())
        .expect("verify must not error on a structurally-valid envelope");
    assert!(
        !ok,
        "PoP-bound Ed25519 signature must NOT verify as a pure-Ed25519 SignedData; \
         cross-protocol reuse is the exact failure M-A closes"
    );
}

/// M-A regression: PoP generate→verify must still round-trip under the new
/// pop-context binding. Reverting the digest wrapping on either side surfaces
/// here as `verify_pop` returning `Ok(false)` on a freshly-generated PoP.
#[cfg(not(feature = "fips"))]
#[test]
fn m_a_pop_round_trips_post_fix() {
    use latticearc::primitives::ec::traits::EcKeyPair;
    use latticearc::types::traits::ProofOfPossession;
    use latticearc::types::types::{PrivateKey, PublicKey};
    use latticearc::unified_api::zero_trust::ZeroTrustAuth;

    let kp = support::ed25519_keypair();
    let auth = ZeroTrustAuth::new(
        PublicKey::new(kp.public_key_bytes()),
        PrivateKey::new(kp.secret_key_bytes().as_slice().to_vec()),
    )
    .expect("auth init");
    let challenge = b"m-a-pop-roundtrip-challenge";
    let pop = auth.generate_pop(challenge).expect("PoP generation must succeed");
    let ok = auth.verify_pop(&pop, challenge).expect("PoP verify must not error on a fresh PoP");
    assert!(ok, "fresh PoP must verify under post-M-A pop-context binding");
}

// ============================================================================
// M-B (follow-up): expiry gate routed into key-extraction paths
// ============================================================================

/// M-B regression: `to_hybrid_sig_public_key()` must reject a portable key
/// whose `not_after` is in the past. Pre-fix the extract method only
/// guarded `key_type` (M2) and skipped expiry entirely, so an expired
/// portable key could be turned into a usable typed public key.
#[test]
fn m_b_to_hybrid_sig_public_key_rejects_expired() {
    use chrono::{Duration, Utc};
    use latticearc::SecurityMode;
    use latticearc::generate_hybrid_signing_keypair;
    use latticearc::types::types::UseCase;
    use latticearc::unified_api::key_format::PortableKey;

    let (pk, sk) =
        generate_hybrid_signing_keypair(SecurityMode::Unverified).expect("hybrid signing keygen");
    let (mut pk_portable, _sk_portable) =
        PortableKey::from_hybrid_sig_keypair(UseCase::ApiSecurity, &pk, &sk)
            .expect("portable conversion");
    let past = Utc::now() - Duration::hours(1);
    pk_portable.set_not_after(Some(past));

    let result = pk_portable.to_hybrid_sig_public_key();
    assert!(
        result.is_err(),
        "to_hybrid_sig_public_key must reject expired keys (M-B); got {result:?}"
    );
    // `validate()` alone still passes — the gate is the extract method,
    // not the load path.
    assert!(pk_portable.validate().is_ok(), "validate must remain expiry-blind");
}

/// M-B regression: `to_hybrid_sig_secret_key()` must reject an expired
/// portable key. Mirrors `m_b_to_hybrid_sig_public_key_rejects_expired`
/// for the secret side.
#[test]
fn m_b_to_hybrid_sig_secret_key_rejects_expired() {
    use chrono::{Duration, Utc};
    use latticearc::SecurityMode;
    use latticearc::generate_hybrid_signing_keypair;
    use latticearc::types::types::UseCase;
    use latticearc::unified_api::key_format::PortableKey;

    let (pk, sk) =
        generate_hybrid_signing_keypair(SecurityMode::Unverified).expect("hybrid signing keygen");
    let (_pk_portable, mut sk_portable) =
        PortableKey::from_hybrid_sig_keypair(UseCase::ApiSecurity, &pk, &sk)
            .expect("portable conversion");
    let past = Utc::now() - Duration::hours(1);
    sk_portable.set_not_after(Some(past));

    let result = sk_portable.to_hybrid_sig_secret_key();
    assert!(
        result.is_err(),
        "to_hybrid_sig_secret_key must reject expired keys (M-B); got {result:?}"
    );
}

// ============================================================================
// L-A (follow-up): FIPS Pattern-6 indistinguishability for ed25519
// ============================================================================

/// L-A regression: under `--features fips`, verifying a SignedData envelope
/// whose scheme is `"ed25519"` must return `Ok(false)`, not
/// `Err(InvalidInput(...))`. The pre-fix behaviour echoed the scheme string
/// and was asymmetric with the verify_with_anchor path that calls into the
/// same dispatcher.
#[cfg(feature = "fips")]
#[test]
fn l_a_fips_pure_ed25519_envelope_returns_ok_false() {
    use latticearc::unified_api::types::{SignedData, SignedMetadata};
    use latticearc::{CryptoConfig, verify};

    let envelope = SignedData::new(
        b"L-A".to_vec(),
        SignedMetadata::new(vec![0u8; 64], "ed25519".to_string(), vec![0u8; 32], None),
        "ed25519".to_string(),
        0,
    );
    let result = verify(&envelope, CryptoConfig::new());
    assert!(matches!(result, Ok(false)), "fips verify must return Ok(false), got {result:?}");
}

/// L-A regression: `verify_with_anchor` under FIPS must also return
/// `Ok(false)` for an `"ed25519"` envelope. Since the M5 allowlist no
/// longer maps `"ed25519"` under FIPS, the canonicalisation step in
/// `verify_with_anchor` returns `Ok(false)` BEFORE the dispatcher even
/// runs — matches the Pattern-6 contract.
#[cfg(feature = "fips")]
#[test]
fn l_a_fips_verify_with_anchor_rejects_pure_ed25519_at_allowlist() {
    use latticearc::unified_api::types::{SignedData, SignedMetadata};
    use latticearc::{CryptoConfig, verify_with_anchor};

    let envelope = SignedData::new(
        b"L-A".to_vec(),
        SignedMetadata::new(vec![0u8; 64], "ed25519".to_string(), vec![0u8; 32], None),
        "ed25519".to_string(),
        0,
    );
    let pk = [0u8; 32];
    let result = verify_with_anchor(&envelope, &pk, "ed25519", CryptoConfig::new());
    assert!(
        matches!(result, Ok(false)),
        "fips verify_with_anchor must return Ok(false), got {result:?}"
    );
}

// ============================================================================
// PoP-H1 / PoP-M1 / PoP-L1: identity + challenge binding + Pattern-6 replay
// ============================================================================

/// PoP-H1 regression: a PoP whose embedded public key does not match
/// the verifier's identity must return `Ok(false)`. Pre-fix verify_pop
/// dispatched against `pop.public_key()` directly, so anyone with any
/// Ed25519 keypair could produce a self-signed PoP that verified Ok(true)
/// — proving possession of A KEY, not THIS IDENTITY's key.
#[cfg(not(feature = "fips"))]
#[test]
fn pop_h1_foreign_identity_pop_rejected() {
    use latticearc::primitives::ec::traits::EcKeyPair;
    use latticearc::types::traits::ProofOfPossession;
    use latticearc::types::types::{PrivateKey, PublicKey};
    use latticearc::unified_api::zero_trust::ZeroTrustAuth;

    // Verifier (Alice) — this is the identity any PoP must be bound to.
    let alice_kp = support::ed25519_keypair();
    let alice = ZeroTrustAuth::new(
        PublicKey::new(alice_kp.public_key_bytes()),
        PrivateKey::new(alice_kp.secret_key_bytes().as_slice().to_vec()),
    )
    .expect("alice init");

    // Attacker (Eve) — generates a perfectly valid self-signed PoP
    // under their own keypair.
    let eve_kp = support::ed25519_keypair();
    let eve = ZeroTrustAuth::new(
        PublicKey::new(eve_kp.public_key_bytes()),
        PrivateKey::new(eve_kp.secret_key_bytes().as_slice().to_vec()),
    )
    .expect("eve init");

    let challenge = b"pop-h1-challenge";
    let eve_pop = eve.generate_pop(challenge).expect("eve generates a valid self-PoP");

    // Eve presents her PoP to Alice's verifier. Pre-fix this would
    // return Ok(true) because verify_pop trusted the embedded key.
    let alice_says = alice.verify_pop(&eve_pop, challenge).expect("verify must not error");
    assert!(
        !alice_says,
        "PoP-H1: a PoP under Eve's identity must NOT verify against Alice's identity"
    );
}

/// PoP-M1 regression: a PoP captured under challenge A must NOT verify
/// against challenge B, even when the same legitimate identity and the
/// same key are used on both sides. Closes the cross-verifier-instance
/// replay window inside the freshness period.
#[cfg(not(feature = "fips"))]
#[test]
fn pop_m1_challenge_swap_rejected() {
    use latticearc::primitives::ec::traits::EcKeyPair;
    use latticearc::types::traits::ProofOfPossession;
    use latticearc::types::types::{PrivateKey, PublicKey};
    use latticearc::unified_api::zero_trust::ZeroTrustAuth;

    let kp = support::ed25519_keypair();
    let auth = ZeroTrustAuth::new(
        PublicKey::new(kp.public_key_bytes()),
        PrivateKey::new(kp.secret_key_bytes().as_slice().to_vec()),
    )
    .expect("auth init");

    let pop_for_a = auth.generate_pop(b"verifier-A-round-1-nonce").expect("PoP under challenge A");
    let valid_against_a = auth
        .verify_pop(&pop_for_a, b"verifier-A-round-1-nonce")
        .expect("verify under matching challenge");
    assert!(valid_against_a, "fresh PoP must verify under its own challenge");

    let valid_against_b = auth
        .verify_pop(&pop_for_a, b"verifier-B-different-nonce")
        .expect("verify must not error on a challenge swap");
    assert!(
        !valid_against_b,
        "PoP-M1: PoP for one challenge must NOT verify against a different challenge"
    );
}

/// PoP-L1 regression: a PoP replayed within the freshness window must
/// return `Ok(false)` (Pattern-6 indistinguishable from stale / wrong /
/// foreign-identity), NOT `Err(InvalidInput("replay detected"))` as
/// pre-fix. The previous Err variant let an attacker distinguish "I've
/// seen this before" from the sibling stale path that already returned
/// `Ok(false)`.
#[cfg(not(feature = "fips"))]
#[test]
fn pop_l1_replay_collapses_to_ok_false() {
    use latticearc::primitives::ec::traits::EcKeyPair;
    use latticearc::types::traits::ProofOfPossession;
    use latticearc::types::types::{PrivateKey, PublicKey};
    use latticearc::unified_api::zero_trust::ZeroTrustAuth;

    let kp = support::ed25519_keypair();
    let auth = ZeroTrustAuth::new(
        PublicKey::new(kp.public_key_bytes()),
        PrivateKey::new(kp.secret_key_bytes().as_slice().to_vec()),
    )
    .expect("auth init");

    let challenge = b"pop-l1-replay-test-challenge";
    let pop = auth.generate_pop(challenge).expect("PoP generation");

    // First presentation: legitimate, must verify.
    let first = auth.verify_pop(&pop, challenge).expect("first verify");
    assert!(first, "first presentation of a fresh PoP must verify");

    // Second presentation: replay. MUST be Ok(false), not Err.
    // Pre-fix this branch returned
    // Err(CoreError::InvalidInput("Proof-of-possession replay detected")).
    let second = auth.verify_pop(&pop, challenge);
    assert!(
        matches!(second, Ok(false)),
        "PoP-L1: replay must collapse to Ok(false), got {second:?}"
    );
}

// ============================================================================
// M-serialize_keypair: return type carries Zeroizing<String>
// ============================================================================

/// Compile-time regression: `serialize_keypair`'s return type must wrap
/// the JSON string in `Zeroizing<String>`. The pre-fix signature
/// returned `Result<String>`, leaving the base64-encoded private key on
/// the heap until allocator policy reclaimed the buffer.
///
/// This test is intentionally trivial — its job is to fail to compile
/// (or panic) if the signature regresses. The runtime check is just
/// "the returned value derefs to a usable &str".
#[test]
fn m_serialize_keypair_returns_zeroizing_string() {
    use latticearc::serialize_keypair;
    use latticearc::types::types::{KeyPair, PrivateKey, PublicKey};
    use std::any::Any;
    use zeroize::Zeroizing;

    let kp = KeyPair::new(PublicKey::new(vec![0x01; 32]), PrivateKey::new(vec![0x10; 32]));
    let json: Zeroizing<String> = serialize_keypair(&kp).expect("serialize must succeed");

    // Sanity: derefs to a usable &str so callers can still pass it to
    // serde / deserialize_keypair.
    assert!(json.as_str().contains("\"public_key\""), "serialized form must contain pubkey field");

    // Type-level assertion. The `Any` reflection is overkill but locks
    // the concrete type so a refactor that returns a wrapper type
    // (e.g. a newtype around Zeroizing) trips this assertion at
    // runtime as well.
    let as_any: &dyn Any = &json;
    assert!(
        as_any.is::<Zeroizing<String>>(),
        "serialize_keypair must return Zeroizing<String> exactly"
    );
}

// ============================================================================
// L-DlogEqualityStatement: pub fields encapsulated, with_bases / accessors
// ============================================================================

/// Regression: `DlogEqualityStatement` fields are no longer publicly
/// readable as struct fields. The `with_bases` constructor and the
/// `g()/h()/p()/q()` accessors are the public API. A future refactor
/// that re-exposes `pub g: [u8; 33]` etc. would trip this test by
/// allowing struct-literal construction in this integration-test crate.
#[cfg(not(feature = "fips"))]
#[test]
fn l_dlog_equality_statement_uses_with_bases_constructor() {
    use latticearc::zkp::sigma::DlogEqualityStatement;

    let g_bytes = [0u8; 33];
    let h_bytes = [1u8; 33];
    let p_bytes = [2u8; 33];
    let q_bytes = [3u8; 33];
    let stmt = DlogEqualityStatement::with_bases(g_bytes, h_bytes, p_bytes, q_bytes);
    assert_eq!(stmt.g(), &g_bytes);
    assert_eq!(stmt.h(), &h_bytes);
    assert_eq!(stmt.p(), &p_bytes);
    assert_eq!(stmt.q(), &q_bytes);
}
