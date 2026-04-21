//! Cross-implementation validation for SLH-DSA (FIPS 205).
//!
//! Two independent implementations — `fips205` (audited pure Rust, used by
//! this crate) and `pqcrypto-sphincsplus` (PQClean C reference bindings) —
//! tested for byte-format agreement and cross-verification where the
//! specification allows.
//!
//! ## Scope note on cross-verification
//!
//! FIPS 205 §10.2 defines `slh_sign(M, ctx, SK)` which binds a `context`
//! string into the signed message via a domain-separation header:
//! `M' = 0x00 || len(ctx) || ctx || M`. The pqcrypto-sphincsplus C binding
//! exposes `detached_sign(msg, sk)` without an explicit context argument;
//! whether it applies the FIPS 205 header internally depends on the
//! PQClean release the binding wraps. Key and signature sizes should
//! match unconditionally (they are algorithm parameters, not per-message
//! encoding). Cross-verification of actual signatures is attempted and
//! documented as a known incompatibility if the context binding diverges.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use latticearc::primitives::sig::slh_dsa::{SigningKey, SlhDsaSecurityLevel, VerifyingKey};
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _};

// =============================================================================
// Key / signature size agreement (unconditional)
// =============================================================================

#[test]
fn slh_dsa_shake_128s_sizes_agree() {
    use pqcrypto_sphincsplus::sphincsshake128ssimple as pqc;
    assert_eq!(pqc::public_key_bytes(), SlhDsaSecurityLevel::Shake128s.public_key_size());
    assert_eq!(pqc::secret_key_bytes(), SlhDsaSecurityLevel::Shake128s.secret_key_size());
    assert_eq!(pqc::signature_bytes(), SlhDsaSecurityLevel::Shake128s.signature_size());
}

#[test]
fn slh_dsa_shake_192s_sizes_agree() {
    use pqcrypto_sphincsplus::sphincsshake192ssimple as pqc;
    assert_eq!(pqc::public_key_bytes(), SlhDsaSecurityLevel::Shake192s.public_key_size());
    assert_eq!(pqc::secret_key_bytes(), SlhDsaSecurityLevel::Shake192s.secret_key_size());
    assert_eq!(pqc::signature_bytes(), SlhDsaSecurityLevel::Shake192s.signature_size());
}

#[test]
fn slh_dsa_shake_256s_sizes_agree() {
    use pqcrypto_sphincsplus::sphincsshake256ssimple as pqc;
    assert_eq!(pqc::public_key_bytes(), SlhDsaSecurityLevel::Shake256s.public_key_size());
    assert_eq!(pqc::secret_key_bytes(), SlhDsaSecurityLevel::Shake256s.secret_key_size());
    assert_eq!(pqc::signature_bytes(), SlhDsaSecurityLevel::Shake256s.signature_size());
}

// =============================================================================
// Documented cross-impl divergence: FIPS 205 §10.2 context header
// =============================================================================
//
// FIPS 205 §10.2 mandates wrapping the signed message with a domain-separation
// header: `M' = 0x00 || len(ctx) || ctx || M`. Our `fips205` dependency
// applies this wrapping (via `try_sign(message, ctx, hedged)`), while the
// `pqcrypto-sphincsplus` PQClean binding implements the pre-standardization
// SPHINCS+ signing (no context wrapping).
//
// Result: byte layouts (key sizes, signature sizes) are identical — covered
// by the three `_sizes_agree` tests above — but signatures are not
// cross-verifiable. The tests below *assert the divergence exists* so that
// a future PQClean update aligning with FIPS 205 will surface as a test
// failure, prompting us to re-enable full cross-verification.

#[test]
fn slh_dsa_shake_128s_pqcrypto_sign_fips205_rejects_due_to_ctx_header() {
    use pqcrypto_sphincsplus::sphincsshake128ssimple as pqc;
    let (pk_pqc, sk_pqc) = pqc::keypair();
    let message = b"cross-impl SLH-DSA-SHAKE-128s: pqcrypto signs, fips205 verifies";
    let sig_pqc = pqc::detached_sign(message, &sk_pqc);

    let pk_fips = VerifyingKey::new(SlhDsaSecurityLevel::Shake128s, pk_pqc.as_bytes())
        .expect("fips205 must accept pqcrypto public key bytes");

    // With `context=Some(b"")` fips205 prepends the FIPS 205 header, which
    // pqcrypto did not apply when signing. The verification MUST NOT accept
    // the signature — if it starts accepting, the divergence has closed and
    // this test should be replaced with a full cross-verify assertion.
    let verified = pk_fips
        .verify(message, sig_pqc.as_bytes(), b"")
        .expect("fips205 verify must complete without error");
    assert!(
        !verified,
        "FIPS 205 context-header divergence closed — pqcrypto-sphincsplus now \
         FIPS 205-compliant. Replace this test with a positive cross-verify."
    );
}

#[test]
fn slh_dsa_shake_128s_fips205_sign_pqcrypto_rejects_due_to_ctx_header() {
    use pqcrypto_sphincsplus::sphincsshake128ssimple as pqc;
    let (sk_fips, pk_fips) =
        SigningKey::generate(SlhDsaSecurityLevel::Shake128s).expect("fips205 keygen");
    let message = b"cross-impl SLH-DSA-SHAKE-128s: fips205 signs, pqcrypto verifies";
    let sig_fips = sk_fips.sign(message, b"").expect("fips205 sign");

    let pk_pqc = pqc::PublicKey::from_bytes(pk_fips.as_bytes()).unwrap();
    let sig_pqc = pqc::DetachedSignature::from_bytes(&sig_fips).unwrap();

    // fips205's signature embeds the FIPS 205 context header in the signed
    // data; pqcrypto verifies against the bare message and MUST reject.
    // When pqcrypto-sphincsplus ships FIPS 205 support, this call will
    // succeed and the assertion below will fail, flagging the divergence.
    let result = pqc::verify_detached_signature(&sig_pqc, message, &pk_pqc);
    assert!(
        result.is_err(),
        "FIPS 205 context-header divergence closed — pqcrypto-sphincsplus now \
         accepts fips205 signatures. Replace this test with a positive cross-verify."
    );
}
