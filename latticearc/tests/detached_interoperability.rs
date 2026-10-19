//! Independent, fixed detached-signature vectors and format-confusion regressions.
#![cfg(not(feature = "fips"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use aws_lc_rs::signature::{ED25519, UnparsedPublicKey};
use base64::{Engine, engine::general_purpose::STANDARD};
use latticearc::{
    ComplianceMode, CoreError, CryptoConfig, DetachedSignature, DetachedSigningKey,
    DetachedVerificationKey, SecurityMode, SignedData, SignedMetadata, sign_detached, sign_ed25519,
    verify_detached_with_key, verify_ed25519, verify_with_anchor,
};
use serde::Deserialize;

#[derive(Deserialize)]
struct Fixtures {
    seed_hex: String,
    vectors: Vec<Vector>,
}

#[derive(Deserialize)]
struct Vector {
    name: String,
    claims_hex: String,
    public_key_hex: String,
    expected_domain: String,
    valid: bool,
    transcript_hex: String,
    record: DetachedSignature,
}

fn fixtures() -> Fixtures {
    serde_json::from_str(include_str!("fixtures/detached-v1.json")).unwrap()
}

#[test]
fn openssl_fixtures_verify_with_pinned_keys() {
    for vector in fixtures().vectors {
        let verified = verify_detached_with_key(
            &hex::decode(&vector.claims_hex).unwrap(),
            &vector.record,
            DetachedVerificationKey::Ed25519(&hex::decode(&vector.public_key_hex).unwrap()),
            &vector.expected_domain,
            CryptoConfig::new(),
        )
        .unwrap();
        assert_eq!(verified, vector.valid, "fixture: {}", vector.name);
    }
}

#[test]
fn signatures_match_openssl_and_verify_with_aws_lc() {
    let fixtures = fixtures();
    let seed = hex::decode(fixtures.seed_hex).unwrap();
    for vector in fixtures.vectors.into_iter().filter(|vector| vector.valid) {
        let signed = sign_detached(
            &hex::decode(&vector.claims_hex).unwrap(),
            DetachedSigningKey::Ed25519(&seed),
            &vector.expected_domain,
            CryptoConfig::new(),
        )
        .unwrap();
        assert_eq!(signed, vector.record, "fixture: {}", vector.name);
        assert_eq!(DetachedSignature::from_json(&signed.to_json().unwrap()).unwrap(), signed);
        // AWS-LC is independent of the Ed25519-dalek implementation used by LatticeArc.
        UnparsedPublicKey::new(&ED25519, hex::decode(&vector.public_key_hex).unwrap())
            .verify(
                &hex::decode(&vector.transcript_hex).unwrap(),
                &STANDARD.decode(&signed.signature).unwrap(),
            )
            .unwrap();
    }
}

#[test]
fn raw_unified_and_detached_formats_are_not_interchangeable() {
    let fixtures = fixtures();
    let vector = &fixtures.vectors[0];
    let seed = hex::decode(fixtures.seed_hex).unwrap();
    let claims = hex::decode(&vector.claims_hex).unwrap();
    let pk = hex::decode(&vector.public_key_hex).unwrap();
    let config = CryptoConfig::new;
    let envelope_vector = fixtures
        .vectors
        .iter()
        .find(|vector| vector.name == "unified-envelope-is-not-detached")
        .unwrap();
    let envelope = SignedData::new(
        claims.clone(),
        SignedMetadata::new(
            STANDARD.decode(&envelope_vector.record.signature).unwrap(),
            "ed25519".to_owned(),
            pk.clone(),
            None,
        ),
        "ed25519".to_owned(),
        0,
    );
    assert!(verify_with_anchor(&envelope, &pk, "ed25519", config()).unwrap());
    let raw = sign_ed25519(&claims, &seed, SecurityMode::Unverified).unwrap();
    assert!(verify_ed25519(&claims, &raw, &pk, SecurityMode::Unverified).unwrap());
    assert!(
        !verify_ed25519(&claims, &envelope.metadata.signature, &pk, SecurityMode::Unverified)
            .unwrap()
    );
    let detached_bytes = STANDARD.decode(&vector.record.signature).unwrap();
    assert!(!verify_ed25519(&claims, &detached_bytes, &pk, SecurityMode::Unverified).unwrap());
    for signature in [raw, envelope.metadata.signature.clone()] {
        let mut record = vector.record.clone();
        record.signature = STANDARD.encode(signature);
        assert!(
            !verify_detached_with_key(
                &claims,
                &record,
                DetachedVerificationKey::Ed25519(&pk),
                &vector.expected_domain,
                CryptoConfig::new()
            )
            .unwrap()
        );
    }
    let mut relabeled_envelope = envelope;
    relabeled_envelope.metadata.signature = detached_bytes;
    assert!(!verify_with_anchor(&relabeled_envelope, &pk, "ed25519", config()).unwrap());
}

#[test]
fn parser_rejects_ambiguous_or_malformed_records() {
    let fixtures = fixtures();
    let record = &fixtures.vectors[0].record;
    let json = record.to_json().unwrap();
    for malformed in [
        json.replacen('{', "{\"version\":1,", 1),
        json.replacen('{', "{\"public_key\":\"attacker-key\",", 1),
        json.replace("\"version\":1", "\"version\":2"),
        json.replace("\"version\":1,", ""),
        json.replace("ed25519", "Ed25519"),
        format!("{json} trailing-data"),
        " ".repeat(8193),
    ] {
        assert!(DetachedSignature::from_json(&malformed).is_err());
    }
    for signature in ["!".repeat(88), STANDARD.encode([0u8; 63]), STANDARD.encode([0u8; 65])] {
        let mut malformed = record.clone();
        malformed.signature = signature;
        assert!(malformed.to_json().is_err());
        assert!(DetachedSignature::from_json(&serde_json::to_string(&malformed).unwrap()).is_err());
    }
    // For 64 zero bytes the canonical final quantum is AA==. AB== carries
    // nonzero unused bits, even though permissive decoders produce the same bytes.
    let mut noncanonical = record.clone();
    noncanonical.signature = format!("{}AB==", "A".repeat(84));
    assert!(DetachedSignature::from_json(&serde_json::to_string(&noncanonical).unwrap()).is_err());
}

#[test]
fn domain_key_and_resource_limits_are_enforced() {
    let fixtures = fixtures();
    let vector = &fixtures.vectors[0];
    let seed = hex::decode(fixtures.seed_hex).unwrap();
    let pk = hex::decode(&vector.public_key_hex).unwrap();
    for domain in ["", "with space", "nul\0byte", "unicode-é", &"a".repeat(256)] {
        assert!(
            sign_detached(
                b"claims",
                DetachedSigningKey::Ed25519(&seed),
                domain,
                CryptoConfig::new()
            )
            .is_err()
        );
        assert!(
            verify_detached_with_key(
                b"claims",
                &vector.record,
                DetachedVerificationKey::Ed25519(&pk),
                domain,
                CryptoConfig::new()
            )
            .is_err()
        );
    }
    for key in [vec![1u8; 31], vec![1u8; 33], vec![1u8; 64]] {
        assert!(
            sign_detached(
                b"claims",
                DetachedSigningKey::Ed25519(&key),
                "domain",
                CryptoConfig::new()
            )
            .is_err()
        );
        assert!(
            verify_detached_with_key(
                b"claims",
                &vector.record,
                DetachedVerificationKey::Ed25519(&key),
                &vector.expected_domain,
                CryptoConfig::new()
            )
            .is_err()
        );
    }
    let oversized = vec![0u8; 64 * 1024];
    assert!(
        sign_detached(
            &oversized,
            DetachedSigningKey::Ed25519(&seed),
            "domain",
            CryptoConfig::new()
        )
        .is_err()
    );
    assert!(
        verify_detached_with_key(
            &oversized,
            &vector.record,
            DetachedVerificationKey::Ed25519(&pk),
            &vector.expected_domain,
            CryptoConfig::new()
        )
        .is_err()
    );
}

#[test]
fn domain_and_claims_have_unambiguous_boundaries() {
    let seed = hex::decode(fixtures().seed_hex).unwrap();
    let a =
        sign_detached(b"bc", DetachedSigningKey::Ed25519(&seed), "a", CryptoConfig::new()).unwrap();
    let b =
        sign_detached(b"c", DetachedSigningKey::Ed25519(&seed), "ab", CryptoConfig::new()).unwrap();
    assert_ne!(a.signature, b.signature);
}

#[test]
fn weak_public_key_and_noncanonical_scalar_are_rejected() {
    let fixtures = fixtures();
    let vector = &fixtures.vectors[0];
    let claims = hex::decode(&vector.claims_hex).unwrap();
    let pk = hex::decode(&vector.public_key_hex).unwrap();
    // Identity point key and R, zero S: reject the small-order forgery.
    let mut identity_key = [0u8; 32];
    identity_key[0] = 1;
    let mut forged = [0u8; 64];
    forged[0] = 1;
    let mut record = vector.record.clone();
    record.signature = STANDARD.encode(forged);
    assert!(
        !verify_detached_with_key(
            &claims,
            &record,
            DetachedVerificationKey::Ed25519(&identity_key),
            &vector.expected_domain,
            CryptoConfig::new()
        )
        .unwrap()
    );
    let mut bytes = STANDARD.decode(&vector.record.signature).unwrap();
    bytes[32..].fill(0xff);
    record.signature = STANDARD.encode(bytes);
    assert!(
        !verify_detached_with_key(
            &claims,
            &record,
            DetachedVerificationKey::Ed25519(&pk),
            &vector.expected_domain,
            CryptoConfig::new()
        )
        .unwrap()
    );
}

#[test]
fn fips_requiring_compliance_rejects_ed25519_before_signing() {
    let fixtures = fixtures();
    let vector = &fixtures.vectors[0];
    let seed = hex::decode(&fixtures.seed_hex).unwrap();
    let pk = hex::decode(&vector.public_key_hex).unwrap();
    for compliance in [ComplianceMode::Fips140_3, ComplianceMode::Cnsa2_0] {
        let config = || CryptoConfig::new().compliance(compliance.clone());
        assert!(matches!(
            sign_detached(b"claims", DetachedSigningKey::Ed25519(&seed), "domain", config()),
            Err(CoreError::FeatureNotAvailable(_))
        ));
        assert!(matches!(
            verify_detached_with_key(
                b"claims",
                &vector.record,
                DetachedVerificationKey::Ed25519(&pk),
                &vector.expected_domain,
                config()
            ),
            Err(CoreError::FeatureNotAvailable(_))
        ));
    }
}
