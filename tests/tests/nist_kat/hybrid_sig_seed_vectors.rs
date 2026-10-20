//! Cross-platform determinism check for seed-based hybrid signing keygen:
//! every platform CI runs on must regenerate the pinned public keys from the
//! pinned seeds. Vector provenance (self-generated):
//! `latticearc_tests::validation::nist_kat::hybrid_sig_seed_kat`.

#![allow(clippy::expect_used)]

use latticearc::generate_hybrid_signing_keypair_from_seed;
use latticearc::hybrid::sig_hybrid::{
    sign_prehashed, sign_with_context, verify_prehashed, verify_with_context,
};
use latticearc::primitives::sig::ml_dsa::MlDsaParameterSet;
use latticearc_tests::validation::nist_kat::decode_hex;
use latticearc_tests::validation::nist_kat::hybrid_sig_seed_kat::HYBRID_SIG_SEED_VECTORS;
use sha2::{Digest, Sha256, Sha512};

fn parameter_set(name: &str) -> MlDsaParameterSet {
    match name {
        "ML-DSA-44" => Some(MlDsaParameterSet::MlDsa44),
        "ML-DSA-65" => Some(MlDsaParameterSet::MlDsa65),
        "ML-DSA-87" => Some(MlDsaParameterSet::MlDsa87),
        _ => None,
    }
    .expect("vector parameter set name is one of ML-DSA-44/65/87")
}

#[test]
fn hybrid_seed_vectors_regenerate_identically() {
    assert_eq!(HYBRID_SIG_SEED_VECTORS.len(), 6, "2 seeds x 3 parameter sets");
    for v in HYBRID_SIG_SEED_VECTORS {
        let set = parameter_set(v.parameter_set);
        let seed_bytes = decode_hex(v.seed).expect("seed hex");
        let seed: [u8; 32] = seed_bytes.as_slice().try_into().expect("32-byte seed");
        let (pk, sk) = generate_hybrid_signing_keypair_from_seed(&seed, set).expect("keygen");
        assert_eq!(pk.parameter_set(), set);
        assert_eq!(
            hex::encode(pk.ml_dsa_pk()),
            v.ml_dsa_pk,
            "{} seed {}: ML-DSA public key",
            v.parameter_set,
            v.seed
        );
        assert_eq!(
            hex::encode(pk.ed25519_pk()),
            v.ed25519_pk,
            "{} seed {}: Ed25519 public key",
            v.parameter_set,
            v.seed
        );
        assert_eq!(
            hex::encode(Sha256::digest(sk.expose_ml_dsa_secret())),
            v.ml_dsa_sk_sha256,
            "{} seed {}: ML-DSA secret key digest",
            v.parameter_set,
            v.seed
        );
        assert_eq!(
            hex::encode(Sha256::digest(sk.expose_ed25519_secret())),
            v.ed25519_sk_sha256,
            "{} seed {}: Ed25519 secret digest",
            v.parameter_set,
            v.seed
        );

        // The regenerated keypair is usable in both 0.13 transcript modes.
        let ctx = b"vault/v1/root-sig";
        let sig = sign_with_context(&sk, b"manifest", ctx).expect("sign_with_context");
        assert!(verify_with_context(&pk, b"manifest", &sig, ctx).expect("verify_with_context"));
        let digest: [u8; 64] = Sha512::digest(b"manifest").into();
        let sig = sign_prehashed(&sk, &digest, ctx).expect("sign_prehashed");
        assert!(verify_prehashed(&pk, &digest, &sig, ctx).expect("verify_prehashed"));
    }
}
