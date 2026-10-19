//! Pure post-quantum detached signatures, independent OpenSSL vectors and policy gates.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use aws_lc_rs::signature::{ML_DSA_44, ML_DSA_65, ML_DSA_87, UnparsedPublicKey};
use base64::{Engine, engine::general_purpose::STANDARD};
use latticearc::primitives::sig::ml_dsa::{MlDsaParameterSet, MlDsaPublicKey, MlDsaSecretKey};
use latticearc::{
    CoreError, CryptoConfig, CryptoScheme, DetachedSignature, SecurityLevel, UseCase,
    generate_detached_keypair, sign_detached, verify_detached_with_key,
};
use serde::Deserialize;

#[derive(Deserialize)]
struct Fixtures {
    sets: Vec<KeySet>,
}
#[derive(Deserialize)]
struct KeySet {
    algorithm: String,
    public_key_hex: String,
    secret_key_hex: String,
    wrong_public_key_hex: String,
    vectors: Vec<Vector>,
}
#[derive(Deserialize)]
struct Vector {
    name: String,
    claims_hex: String,
    expected_domain: String,
    wrong_key: bool,
    valid: bool,
    transcript_hex: String,
    record: DetachedSignature,
}

fn fixtures() -> Fixtures {
    serde_json::from_str(include_str!("fixtures/detached-pq-v1.json")).unwrap()
}

fn parameters(name: &str) -> MlDsaParameterSet {
    match name {
        "ml-dsa-44" => MlDsaParameterSet::MlDsa44,
        "ml-dsa-65" => MlDsaParameterSet::MlDsa65,
        _ => MlDsaParameterSet::MlDsa87,
    }
}

#[test]
fn openssl_pq_fixtures_verify_and_reject_all_negative_cases() {
    for set in fixtures().sets {
        let ps = parameters(&set.algorithm);
        let pk = MlDsaPublicKey::from_bytes(&hex::decode(set.public_key_hex).unwrap(), ps).unwrap();
        let wrong_pk =
            MlDsaPublicKey::from_bytes(&hex::decode(set.wrong_public_key_hex).unwrap(), ps)
                .unwrap();
        for vector in set.vectors {
            let key = if vector.wrong_key { &wrong_pk } else { &pk };
            let verified = verify_detached_with_key(
                &hex::decode(&vector.claims_hex).unwrap(),
                &vector.record,
                key,
                &vector.expected_domain,
                CryptoConfig::new(),
            )
            .unwrap();
            assert_eq!(verified, vector.valid, "{}: {}", set.algorithm, vector.name);
            if vector.valid {
                assert_eq!(
                    DetachedSignature::from_json(&vector.record.to_json().unwrap()).unwrap(),
                    vector.record
                );
            }
        }
    }
}

#[test]
fn randomized_pq_signatures_verify_with_independent_aws_lc() {
    for set in fixtures().sets {
        let ps = parameters(&set.algorithm);
        let pk = hex::decode(&set.public_key_hex).unwrap();
        let sk = MlDsaSecretKey::from_bytes(&hex::decode(set.secret_key_hex).unwrap(), ps).unwrap();
        let verification_algorithm = match ps {
            MlDsaParameterSet::MlDsa44 => &ML_DSA_44,
            MlDsaParameterSet::MlDsa65 => &ML_DSA_65,
            _ => &ML_DSA_87,
        };
        for vector in set.vectors.into_iter().filter(|vector| vector.valid) {
            let signed = sign_detached(
                &hex::decode(&vector.claims_hex).unwrap(),
                &sk,
                &vector.expected_domain,
                CryptoConfig::new(),
            )
            .unwrap();
            assert_eq!(signed.algorithm, set.algorithm);
            assert_eq!(STANDARD.decode(&signed.signature).unwrap().len(), ps.signature_size());
            UnparsedPublicKey::new(verification_algorithm, &pk)
                .verify(
                    &hex::decode(vector.transcript_hex).unwrap(),
                    &STANDARD.decode(&signed.signature).unwrap(),
                )
                .unwrap();
        }
    }
}

#[test]
fn default_api_is_pq_and_security_levels_select_typed_keys() {
    let (pk, sk) = generate_detached_keypair(CryptoConfig::new()).unwrap();
    assert_eq!(pk.parameter_set(), MlDsaParameterSet::MlDsa65);
    let signed = sign_detached(b"claims", &sk, "example.com/claims", CryptoConfig::new()).unwrap();
    assert_eq!(signed.algorithm, "ml-dsa-65");
    assert!(
        verify_detached_with_key(
            b"claims",
            &signed,
            &pk,
            "example.com/claims",
            CryptoConfig::new()
        )
        .unwrap()
    );
    for (level, expected) in [
        (SecurityLevel::Standard, MlDsaParameterSet::MlDsa44),
        (SecurityLevel::High, MlDsaParameterSet::MlDsa65),
        (SecurityLevel::Maximum, MlDsaParameterSet::MlDsa87),
    ] {
        let (public, secret) =
            generate_detached_keypair(CryptoConfig::new().security_level(level)).unwrap();
        assert_eq!(public.parameter_set(), expected);
        let signed =
            sign_detached(b"claims", &secret, "domain", CryptoConfig::new().security_level(level))
                .unwrap();
        assert!(
            verify_detached_with_key(
                b"claims",
                &signed,
                &public,
                "domain",
                CryptoConfig::new().security_level(level)
            )
            .unwrap()
        );
    }
}

#[test]
fn minimum_strength_and_unsupported_policy_are_enforced() {
    let (pk, sk) = generate_detached_keypair(CryptoConfig::new()).unwrap();
    let signed = sign_detached(b"claims", &sk, "domain", CryptoConfig::new()).unwrap();
    assert!(sign_detached(b"claims", &sk, "domain", CryptoConfig::new().max_age(60)).is_err());
    assert!(
        verify_detached_with_key(
            b"claims",
            &signed,
            &pk,
            "domain",
            CryptoConfig::new().max_age(60)
        )
        .is_err()
    );
    assert!(
        sign_detached(
            b"claims",
            &sk,
            "domain",
            CryptoConfig::new().security_level(SecurityLevel::Maximum)
        )
        .is_err()
    );
    assert!(
        verify_detached_with_key(
            b"claims",
            &signed,
            &pk,
            "domain",
            CryptoConfig::new().security_level(SecurityLevel::Maximum)
        )
        .is_err()
    );
    assert!(
        sign_detached(
            b"claims",
            &sk,
            "domain",
            CryptoConfig::new().force_scheme(CryptoScheme::Asymmetric)
        )
        .is_err()
    );
    assert!(
        generate_detached_keypair(CryptoConfig::new().force_scheme(CryptoScheme::Hybrid)).is_err()
    );
    assert!(sign_detached(&vec![0u8; 64 * 1024], &sk, "domain", CryptoConfig::new()).is_err());
    assert!(
        verify_detached_with_key(
            &vec![0u8; 64 * 1024],
            &signed,
            &pk,
            "domain",
            CryptoConfig::new()
        )
        .is_err()
    );
    let mut alias = signed;
    alias.algorithm = "pq-ml-dsa-65".into();
    assert!(DetachedSignature::from_json(&serde_json::to_string(&alias).unwrap()).is_err());
    assert!(
        !verify_detached_with_key(b"claims", &alias, &pk, "domain", CryptoConfig::new()).unwrap()
    );
}

#[cfg(not(feature = "fips"))]
#[test]
fn a_valid_classical_signature_cannot_downgrade_a_pq_key() {
    use latticearc::{CryptoMode, DetachedSigningKey, DetachedVerificationKey};
    let (pk, _sk) = generate_detached_keypair(CryptoConfig::new()).unwrap();
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/detached-v1.json")).unwrap();
    let seed = hex::decode(fixture.get("seed_hex").unwrap().as_str().unwrap()).unwrap();
    let ed_pk = hex::decode(
        fixture
            .get("vectors")
            .unwrap()
            .get(0)
            .unwrap()
            .get("public_key_hex")
            .unwrap()
            .as_str()
            .unwrap(),
    )
    .unwrap();
    let signed =
        sign_detached(b"claims", DetachedSigningKey::Ed25519(&seed), "domain", CryptoConfig::new())
            .unwrap();
    assert!(
        verify_detached_with_key(
            b"claims",
            &signed,
            DetachedVerificationKey::Ed25519(&ed_pk),
            "domain",
            CryptoConfig::new()
        )
        .unwrap()
    );
    assert!(
        !verify_detached_with_key(b"claims", &signed, &pk, "domain", CryptoConfig::new()).unwrap()
    );
    assert!(
        sign_detached(
            b"claims",
            DetachedSigningKey::Ed25519(&seed),
            "domain",
            CryptoConfig::new().crypto_mode(CryptoMode::PqOnly)
        )
        .is_err()
    );
    assert!(
        verify_detached_with_key(
            b"claims",
            &signed,
            DetachedVerificationKey::Ed25519(&ed_pk),
            "domain",
            CryptoConfig::new().crypto_mode(CryptoMode::PqOnly)
        )
        .is_err()
    );
}

#[test]
fn boundary_domains_and_empty_claims_round_trip() {
    let (pk, sk) = generate_detached_keypair(CryptoConfig::new()).unwrap();
    let domains = ["!".to_owned(), "~".to_owned(), "!".repeat(255), "~".repeat(255)];
    for domain in &domains {
        for claims in [&b""[..], &b"x"[..]] {
            let signed = sign_detached(claims, &sk, domain, CryptoConfig::new()).unwrap();
            assert_eq!(&signed.domain, domain);
            assert!(
                verify_detached_with_key(claims, &signed, &pk, domain, CryptoConfig::new())
                    .unwrap()
            );
            let parsed = DetachedSignature::from_json(&signed.to_json().unwrap()).unwrap();
            assert_eq!(parsed, signed);
        }
    }
    let empty = sign_detached(b"", &sk, "domain", CryptoConfig::new()).unwrap();
    assert!(!verify_detached_with_key(b"\0", &empty, &pk, "domain", CryptoConfig::new()).unwrap());
}

#[test]
fn use_case_selection_is_a_configuration_error() {
    let config = || CryptoConfig::new().use_case(UseCase::ApiSecurity);
    let (pk, sk) = generate_detached_keypair(CryptoConfig::new()).unwrap();
    let signed = sign_detached(b"claims", &sk, "domain", CryptoConfig::new()).unwrap();
    assert!(matches!(generate_detached_keypair(config()), Err(CoreError::ConfigurationError(_))));
    assert!(matches!(
        sign_detached(b"claims", &sk, "domain", config()),
        Err(CoreError::ConfigurationError(_))
    ));
    assert!(matches!(
        verify_detached_with_key(b"claims", &signed, &pk, "domain", config()),
        Err(CoreError::ConfigurationError(_))
    ));
}

#[test]
fn directly_constructed_malformed_records_verify_as_false() {
    let (pk, sk) = generate_detached_keypair(CryptoConfig::new()).unwrap();
    let signed = sign_detached(b"claims", &sk, "domain", CryptoConfig::new()).unwrap();
    let mutations: [fn(&mut DetachedSignature); 6] = [
        |record| record.version = 2,
        |record| record.version = 0,
        |record| record.algorithm = "ML-DSA-65".into(),
        |record| record.signature.truncate(8),
        |record| record.signature = "!".repeat(record.signature.len()),
        |record| record.signature.push_str("AAAA"),
    ];
    for mutate in mutations {
        let mut record = signed.clone();
        mutate(&mut record);
        assert!(
            !verify_detached_with_key(b"claims", &record, &pk, "domain", CryptoConfig::new())
                .unwrap()
        );
    }
    let (pk44, _) =
        generate_detached_keypair(CryptoConfig::new().security_level(SecurityLevel::Standard))
            .unwrap();
    assert!(
        !verify_detached_with_key(
            b"claims",
            &signed,
            &pk44,
            "domain",
            CryptoConfig::new().security_level(SecurityLevel::Standard)
        )
        .unwrap()
    );
}
