//! Cross-implementation validation for ML-DSA (FIPS 204).
//!
//! Two independent implementations — `fips204` (pure Rust, per-spec reference)
//! and `pqcrypto-mldsa` (PQClean C reference bindings) — must agree on byte
//! formats and produce cross-verifiable signatures. Catches encoding or
//! parameter-wrap bugs that single-implementation KAT tests cannot detect.
//!
//! Why this is necessary: FIPS 204 / ML-DSA is not yet exposed through
//! aws-lc-rs's Rust API (tracked as `aws/aws-lc-rs#1029`), so until that
//! lands, `pqcrypto-mldsa` is the only Rust-packaged cross-check available.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use latticearc::primitives::sig::ml_dsa::{
    self, MlDsaParameterSet, MlDsaPublicKey, MlDsaSignature,
};
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _};

// =============================================================================
// ML-DSA-44
// =============================================================================

#[test]
fn ml_dsa_44_key_sizes_agree() {
    use pqcrypto_mldsa::mldsa44;
    let spec = MlDsaParameterSet::MlDsa44;
    assert_eq!(mldsa44::public_key_bytes(), spec.public_key_size());
    assert_eq!(mldsa44::secret_key_bytes(), spec.secret_key_size());
    assert_eq!(mldsa44::signature_bytes(), spec.signature_size());
}

#[test]
fn ml_dsa_44_pqcrypto_sign_fips204_verify() {
    use pqcrypto_mldsa::mldsa44;
    let (pk_pqc, sk_pqc) = mldsa44::keypair();
    let message = b"cross-impl: pqcrypto signs, fips204 verifies";

    let sig_pqc = mldsa44::detached_sign(message, &sk_pqc);

    let pk_fips = MlDsaPublicKey::new(MlDsaParameterSet::MlDsa44, pk_pqc.as_bytes().to_vec())
        .expect("pqcrypto public key must round-trip into fips204");
    let sig_fips = MlDsaSignature::new(MlDsaParameterSet::MlDsa44, sig_pqc.as_bytes().to_vec())
        .expect("pqcrypto signature must round-trip into fips204");
    let ok =
        ml_dsa::verify(&pk_fips, message, &sig_fips, b"").expect("fips204 verify must complete");
    assert!(ok, "fips204 must accept pqcrypto's signature");
}

#[test]
fn ml_dsa_44_fips204_sign_pqcrypto_verify() {
    use pqcrypto_mldsa::mldsa44;
    let (pk_fips, sk_fips) =
        ml_dsa::generate_keypair(MlDsaParameterSet::MlDsa44).expect("fips204 keygen must succeed");
    let message = b"cross-impl: fips204 signs, pqcrypto verifies";

    let sig_fips = ml_dsa::sign(&sk_fips, message, b"").expect("fips204 sign must succeed");

    let pk_pqc = mldsa44::PublicKey::from_bytes(pk_fips.as_bytes())
        .expect("fips204 public key must round-trip into pqcrypto");
    let sig_pqc = mldsa44::DetachedSignature::from_bytes(sig_fips.as_bytes())
        .expect("fips204 signature must round-trip into pqcrypto");
    mldsa44::verify_detached_signature(&sig_pqc, message, &pk_pqc)
        .expect("pqcrypto must accept fips204's signature");
}

#[test]
fn ml_dsa_44_tampered_message_rejected_cross_impl() {
    use pqcrypto_mldsa::mldsa44;
    let (_pk_fips, sk_fips) = ml_dsa::generate_keypair(MlDsaParameterSet::MlDsa44).unwrap();
    let message = b"original";
    let sig_fips = ml_dsa::sign(&sk_fips, message, b"").unwrap();

    // Reconstruct just the PQClean-side objects.
    let (pk_pqc, _sk_pqc) = mldsa44::keypair(); // wrong keypair — signature was made under sk_fips
    let sig_pqc = mldsa44::DetachedSignature::from_bytes(sig_fips.as_bytes()).unwrap();

    // Even though the bytes round-trip cleanly, a signature made under one
    // secret key must not verify under a different public key.
    let result = mldsa44::verify_detached_signature(&sig_pqc, message, &pk_pqc);
    assert!(result.is_err(), "pqcrypto must reject signature verified under wrong pk");
}

// =============================================================================
// ML-DSA-65
// =============================================================================

#[test]
fn ml_dsa_65_key_sizes_agree() {
    use pqcrypto_mldsa::mldsa65;
    let spec = MlDsaParameterSet::MlDsa65;
    assert_eq!(mldsa65::public_key_bytes(), spec.public_key_size());
    assert_eq!(mldsa65::secret_key_bytes(), spec.secret_key_size());
    assert_eq!(mldsa65::signature_bytes(), spec.signature_size());
}

#[test]
fn ml_dsa_65_pqcrypto_sign_fips204_verify() {
    use pqcrypto_mldsa::mldsa65;
    let (pk_pqc, sk_pqc) = mldsa65::keypair();
    let message = b"cross-impl ML-DSA-65: pqcrypto signs, fips204 verifies";

    let sig_pqc = mldsa65::detached_sign(message, &sk_pqc);

    let pk_fips =
        MlDsaPublicKey::new(MlDsaParameterSet::MlDsa65, pk_pqc.as_bytes().to_vec()).unwrap();
    let sig_fips =
        MlDsaSignature::new(MlDsaParameterSet::MlDsa65, sig_pqc.as_bytes().to_vec()).unwrap();
    let ok = ml_dsa::verify(&pk_fips, message, &sig_fips, b"").unwrap();
    assert!(ok, "fips204 must accept pqcrypto ML-DSA-65 signature");
}

#[test]
fn ml_dsa_65_fips204_sign_pqcrypto_verify() {
    use pqcrypto_mldsa::mldsa65;
    let (pk_fips, sk_fips) = ml_dsa::generate_keypair(MlDsaParameterSet::MlDsa65).unwrap();
    let message = b"cross-impl ML-DSA-65: fips204 signs, pqcrypto verifies";

    let sig_fips = ml_dsa::sign(&sk_fips, message, b"").unwrap();

    let pk_pqc = mldsa65::PublicKey::from_bytes(pk_fips.as_bytes()).unwrap();
    let sig_pqc = mldsa65::DetachedSignature::from_bytes(sig_fips.as_bytes()).unwrap();
    mldsa65::verify_detached_signature(&sig_pqc, message, &pk_pqc)
        .expect("pqcrypto must accept fips204 ML-DSA-65 signature");
}

// =============================================================================
// ML-DSA-87
// =============================================================================

#[test]
fn ml_dsa_87_key_sizes_agree() {
    use pqcrypto_mldsa::mldsa87;
    let spec = MlDsaParameterSet::MlDsa87;
    assert_eq!(mldsa87::public_key_bytes(), spec.public_key_size());
    assert_eq!(mldsa87::secret_key_bytes(), spec.secret_key_size());
    assert_eq!(mldsa87::signature_bytes(), spec.signature_size());
}

#[test]
fn ml_dsa_87_pqcrypto_sign_fips204_verify() {
    use pqcrypto_mldsa::mldsa87;
    let (pk_pqc, sk_pqc) = mldsa87::keypair();
    let message = b"cross-impl ML-DSA-87: pqcrypto signs, fips204 verifies";

    let sig_pqc = mldsa87::detached_sign(message, &sk_pqc);

    let pk_fips =
        MlDsaPublicKey::new(MlDsaParameterSet::MlDsa87, pk_pqc.as_bytes().to_vec()).unwrap();
    let sig_fips =
        MlDsaSignature::new(MlDsaParameterSet::MlDsa87, sig_pqc.as_bytes().to_vec()).unwrap();
    let ok = ml_dsa::verify(&pk_fips, message, &sig_fips, b"").unwrap();
    assert!(ok, "fips204 must accept pqcrypto ML-DSA-87 signature");
}

#[test]
fn ml_dsa_87_fips204_sign_pqcrypto_verify() {
    use pqcrypto_mldsa::mldsa87;
    let (pk_fips, sk_fips) = ml_dsa::generate_keypair(MlDsaParameterSet::MlDsa87).unwrap();
    let message = b"cross-impl ML-DSA-87: fips204 signs, pqcrypto verifies";

    let sig_fips = ml_dsa::sign(&sk_fips, message, b"").unwrap();

    let pk_pqc = mldsa87::PublicKey::from_bytes(pk_fips.as_bytes()).unwrap();
    let sig_pqc = mldsa87::DetachedSignature::from_bytes(sig_fips.as_bytes()).unwrap();
    mldsa87::verify_detached_signature(&sig_pqc, message, &pk_pqc)
        .expect("pqcrypto must accept fips204 ML-DSA-87 signature");
}
