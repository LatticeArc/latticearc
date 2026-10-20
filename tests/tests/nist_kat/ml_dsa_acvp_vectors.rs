//! NIST ACVP ML-DSA (FIPS 204) vectors run through the LatticeArc API:
//! Algorithm 6 seed keygen, HashML-DSA signing (byte-exact, with the ACVP
//! `rnd`) and HashML-DSA verification (valid and NIST-mutated cases).
//!
//! Vector provenance: `latticearc_tests::validation::nist_kat::ml_dsa_acvp_kat`.

#![allow(clippy::expect_used)]

use latticearc::primitives::sig::ml_dsa::{
    MlDsaParameterSet, MlDsaPublicKey, MlDsaSecretKey, MlDsaSignature, PrehashAlgorithm,
    generate_keypair_from_seed,
};
use latticearc_tests::validation::nist_kat::decode_hex;
use latticearc_tests::validation::nist_kat::ml_dsa_acvp_kat::{
    HASH_SIGGEN_VECTORS, HASH_SIGVER_VECTORS, KEYGEN_VECTORS,
};
use sha2::Digest;
use sha2::digest::{ExtendableOutput, Update, XofReader};

fn parameter_set(name: &str) -> MlDsaParameterSet {
    match name {
        "ML-DSA-44" => Some(MlDsaParameterSet::MlDsa44),
        "ML-DSA-65" => Some(MlDsaParameterSet::MlDsa65),
        "ML-DSA-87" => Some(MlDsaParameterSet::MlDsa87),
        _ => None,
    }
    .expect("ACVP parameter set name is one of ML-DSA-44/65/87")
}

fn prehash(name: &str) -> PrehashAlgorithm {
    match name {
        "SHA2-256" => Some(PrehashAlgorithm::Sha256),
        "SHA2-512" => Some(PrehashAlgorithm::Sha512),
        "SHAKE-128" => Some(PrehashAlgorithm::Shake128),
        "SHAKE-256" => Some(PrehashAlgorithm::Shake256),
        _ => None,
    }
    .expect("ACVP hashAlg is one PrehashAlgorithm supports")
}

/// Compute `PH(M)` for the ACVP `hashAlg` exactly as FIPS 204 Algorithm 4
/// does (SHAKE output lengths 256 / 512 bits).
fn ph(name: &str, message: &[u8]) -> Vec<u8> {
    match name {
        "SHA2-256" => Some(sha2::Sha256::digest(message).to_vec()),
        "SHA2-512" => Some(sha2::Sha512::digest(message).to_vec()),
        "SHAKE-128" => {
            let mut h = shake::Shake128::default();
            Update::update(&mut h, message);
            let mut out = vec![0u8; 32];
            h.finalize_xof().read(&mut out);
            Some(out)
        }
        "SHAKE-256" => {
            let mut h = shake::Shake256::default();
            Update::update(&mut h, message);
            let mut out = vec![0u8; 64];
            h.finalize_xof().read(&mut out);
            Some(out)
        }
        _ => None,
    }
    .expect("pre-hash implementation exists for every selected hashAlg")
}

#[test]
fn acvp_ml_dsa_keygen_seed_vectors_match_algorithm_6() {
    assert_eq!(KEYGEN_VECTORS.len(), 3, "one keyGen vector per parameter set");
    for v in KEYGEN_VECTORS {
        let set = parameter_set(v.parameter_set);
        let seed_bytes = decode_hex(v.seed).expect("seed hex");
        let seed: [u8; 32] = seed_bytes.as_slice().try_into().expect("32-byte seed");
        let (pk, sk) = generate_keypair_from_seed(set, &seed).expect("keygen from seed");
        assert_eq!(
            pk.as_bytes(),
            decode_hex(v.pk).expect("pk hex").as_slice(),
            "{} tcId {}: public key",
            v.parameter_set,
            v.tc_id
        );
        assert_eq!(
            sk.expose_secret(),
            decode_hex(v.sk).expect("sk hex").as_slice(),
            "{} tcId {}: secret key",
            v.parameter_set,
            v.tc_id
        );
    }
}

#[test]
fn acvp_hash_ml_dsa_siggen_vectors_sign_byte_exact() {
    assert_eq!(HASH_SIGGEN_VECTORS.len(), 11);
    let count = |name: &str| HASH_SIGGEN_VECTORS.iter().filter(|v| v.parameter_set == name).count();
    assert_eq!((count("ML-DSA-44"), count("ML-DSA-65"), count("ML-DSA-87")), (4, 4, 3));
    for v in HASH_SIGGEN_VECTORS {
        let set = parameter_set(v.parameter_set);
        let hash = prehash(v.hash_alg);
        assert!(hash.is_permitted_for(set), "{} with {}", v.parameter_set, v.hash_alg);
        let sk = MlDsaSecretKey::from_bytes(&decode_hex(v.sk).expect("sk hex"), set)
            .expect("ACVP sk parses");
        let pk = MlDsaPublicKey::from_bytes(&decode_hex(v.pk).expect("pk hex"), set)
            .expect("ACVP pk parses");
        let context = decode_hex(v.context).expect("context hex");
        assert!(!context.is_empty());
        let message = decode_hex(v.message).expect("message hex");
        let digest = ph(v.hash_alg, &message);
        let rnd_bytes = decode_hex(v.rnd).expect("rnd hex");
        let rnd: [u8; 32] = rnd_bytes.as_slice().try_into().expect("32-byte rnd");
        let expected = decode_hex(v.signature).expect("signature hex");

        let sig =
            sk.sign_prehashed_with_rnd(&digest, hash, &context, &rnd).expect("HashML-DSA signing");
        assert_eq!(
            sig.as_bytes(),
            expected.as_slice(),
            "{} tcId {} ({}): signature bytes",
            v.parameter_set,
            v.tc_id,
            v.hash_alg
        );
        assert!(
            pk.verify_prehashed(&digest, hash, &sig, &context).expect("verify runs"),
            "{} tcId {}: verify",
            v.parameter_set,
            v.tc_id
        );
        // The ACVP message itself must not verify as pure ML-DSA under the
        // same context: the HashML-DSA domain byte separates the modes.
        assert!(!pk.verify(&message, &sig, &context).expect("verify runs"));
    }
}

#[test]
fn acvp_hash_ml_dsa_sigver_vectors_match_expected_outcome() {
    assert_eq!(HASH_SIGVER_VECTORS.len(), 6);
    let mut passed = 0usize;
    for v in HASH_SIGVER_VECTORS {
        let set = parameter_set(v.parameter_set);
        let hash = prehash(v.hash_alg);
        let pk = MlDsaPublicKey::from_bytes(&decode_hex(v.pk).expect("pk hex"), set)
            .expect("ACVP pk parses");
        let sig = MlDsaSignature::from_bytes(&decode_hex(v.signature).expect("sig hex"), set)
            .expect("ACVP signature has the right length");
        let context = decode_hex(v.context).expect("context hex");
        let message = decode_hex(v.message).expect("message hex");
        let digest = ph(v.hash_alg, &message);
        let result = pk.verify_prehashed(&digest, hash, &sig, &context);
        assert_eq!(
            result.as_ref().ok().copied(),
            Some(v.test_passed),
            "{} tcId {} ({}): got {result:?}",
            v.parameter_set,
            v.tc_id,
            v.reason
        );
        if v.test_passed {
            passed += 1;
        }
    }
    assert_eq!(passed, 1, "exactly one sigVer vector is a valid signature");
}
