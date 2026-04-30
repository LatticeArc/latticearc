//! Round-20 audit behavioral regression tests.
//!
//! Each test asserts a *user-visible* property the corresponding fix
//! is supposed to provide. To be a genuine regression blocker each
//! test must:
//!   1. PASS against the round-20-fixed code.
//!   2. FAIL if the fix is reverted.
//!
//! The second property is what makes the test useful — coverage that
//! still passes after the fix is gone is theatre.

#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::panic)]

use latticearc::types::config::{ProofComplexity, ZeroTrustConfig};
use latticearc::types::traits::ZeroTrustAuthenticable;
use latticearc::unified_api::zero_trust::ZeroTrustAuth;

/// Helper: spin up a `ZeroTrustAuth` at the given complexity from a
/// fresh Ed25519 keypair.
fn auth_at(complexity: ProofComplexity) -> ZeroTrustAuth {
    use latticearc::primitives::ec::ed25519::Ed25519KeyPair;
    use latticearc::primitives::ec::traits::EcKeyPair;
    use latticearc::types::{PrivateKey, PublicKey};

    let kp = Ed25519KeyPair::generate().expect("ed25519 keygen");
    let pk = PublicKey::new(kp.public_key_bytes());
    // `secret_key_bytes()` is `Zeroizing<Vec<u8>>` on Ed25519KeyPair.
    let sk_bytes = kp.secret_key_bytes().to_vec();
    let sk = PrivateKey::new(sk_bytes);
    ZeroTrustAuth::with_config(pk, sk, ZeroTrustConfig::new().with_complexity(complexity))
        .expect("ZeroTrustAuth::with_config")
}

/// Same key, but a fresh `ZeroTrustAuth` built around different config.
/// Pre-round-20, signed-message bytes for Low and Medium were
/// byte-identical, so a Low proof verified as Medium and vice versa.
fn paired_auths(low: ProofComplexity, hi: ProofComplexity) -> (ZeroTrustAuth, ZeroTrustAuth) {
    use latticearc::primitives::ec::ed25519::Ed25519KeyPair;
    use latticearc::primitives::ec::traits::EcKeyPair;
    use latticearc::types::{PrivateKey, PublicKey};

    let kp = Ed25519KeyPair::generate().expect("ed25519 keygen");
    let pk_bytes = kp.public_key_bytes();
    let sk_bytes = kp.secret_key_bytes().to_vec();
    // PrivateKey doesn't impl Clone; build two independent copies of the
    // same bytes so each auth handler owns its own.
    let pk_a = PublicKey::new(pk_bytes.clone());
    let sk_a = PrivateKey::new(sk_bytes.clone());
    let pk_b = PublicKey::new(pk_bytes);
    let sk_b = PrivateKey::new(sk_bytes);
    let a = ZeroTrustAuth::with_config(pk_a, sk_a, ZeroTrustConfig::new().with_complexity(low))
        .expect("auth low");
    let b = ZeroTrustAuth::with_config(pk_b, sk_b, ZeroTrustConfig::new().with_complexity(hi))
        .expect("auth hi");
    (a, b)
}

/// Round-20 audit fix #6: a Low proof must NOT verify as Medium.
///
/// This test fails on pre-round-20 code because Low and Medium produced
/// byte-identical signed messages (`challenge || timestamp`). With the
/// round-20 domain tag, Low signs `challenge || timestamp` while Medium
/// signs `0x02 || challenge || timestamp`, so the Ed25519 signature does
/// not validate when the verifier reconstructs the Medium message.
#[test]
fn round20_fix6_low_proof_does_not_verify_as_medium() {
    let (auth_low, auth_medium) = paired_auths(ProofComplexity::Low, ProofComplexity::Medium);
    let challenge = b"round20-domain-tag-low-vs-medium";

    let proof_low = auth_low.generate_proof(challenge).expect("Low generate");
    // Cross-level verification must reject. The API may return either
    // `Ok(false)` or `Err(VerificationFailed)` depending on where the
    // mismatch is detected (signed-message bytes differ → signature
    // fails → typically Err). Either is acceptable; both must NOT be
    // `Ok(true)`.
    let outcome = auth_medium.verify_proof(&proof_low, challenge);
    let accepted = matches!(outcome, Ok(true));

    assert!(
        !accepted,
        "Low proof verified as Medium — domain-tag separation is missing. \
         Round-20 fix #6 must distinguish Low (challenge||ts) from \
         Medium (0x02||challenge||ts) so cross-level verification fails. \
         Got: {outcome:?}"
    );
}

/// Round-20 audit fix #6 (companion): Medium proof must NOT verify as High.
#[test]
fn round20_fix6_medium_proof_does_not_verify_as_high() {
    let (auth_medium, auth_high) = paired_auths(ProofComplexity::Medium, ProofComplexity::High);
    let challenge = b"round20-domain-tag-medium-vs-high";

    let proof_medium = auth_medium.generate_proof(challenge).expect("Medium generate");
    let outcome = auth_high.verify_proof(&proof_medium, challenge);
    let accepted = matches!(outcome, Ok(true));

    assert!(
        !accepted,
        "Medium proof verified as High — domain tags 0x02 vs 0x03 must differ. Got: {outcome:?}"
    );
}

/// Round-20 audit fix #6 (sanity): same-level Medium roundtrip must still work.
#[test]
fn round20_fix6_medium_self_roundtrip_succeeds() {
    let auth = auth_at(ProofComplexity::Medium);
    let challenge = b"round20-medium-self-roundtrip";
    let proof = auth.generate_proof(challenge).expect("Medium generate");
    let valid = auth.verify_proof(&proof, challenge).expect("verify_proof returns Ok(_)");
    assert!(valid, "Medium proof must verify against Medium config");
}

/// Round-20 audit fix #6 (sanity): same-level High roundtrip must still work.
#[test]
fn round20_fix6_high_self_roundtrip_succeeds() {
    let auth = auth_at(ProofComplexity::High);
    let challenge = b"round20-high-self-roundtrip";
    let proof = auth.generate_proof(challenge).expect("High generate");
    let valid = auth.verify_proof(&proof, challenge).expect("verify_proof returns Ok(_)");
    assert!(valid, "High proof must verify against High config");
}
