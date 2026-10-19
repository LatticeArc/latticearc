//! Property-based tests for detached v1 signatures (pure ML-DSA-65).
//!
//! Tests roundtrip (sign → verify → true, record JSON → record), and rejection
//! of modified claims, a different expected domain and a different key.
//! Keys come from a fixed pool shared across cases; see `proptest_pq_sig.rs`
//! for the pooling rationale.

#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use latticearc::primitives::sig::ml_dsa::{MlDsaPublicKey, MlDsaSecretKey};
use latticearc::{
    CryptoConfig, DetachedSignature, generate_detached_keypair, sign_detached,
    verify_detached_with_key,
};
use proptest::prelude::*;
use std::sync::OnceLock;

/// Number of distinct keypairs shared across all proptest cases.
const POOL_SIZE: usize = 8;

/// Valid domains: 1–255 printable ASCII bytes without space.
const DOMAIN: &str = "[!-~]{1,255}";

fn pool() -> &'static [(MlDsaPublicKey, MlDsaSecretKey)] {
    static POOL: OnceLock<Vec<(MlDsaPublicKey, MlDsaSecretKey)>> = OnceLock::new();
    POOL.get_or_init(|| {
        (0..POOL_SIZE).map(|_| generate_detached_keypair(CryptoConfig::new()).unwrap()).collect()
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn prop_detached_roundtrip(
        key in 0..POOL_SIZE,
        claims in prop::collection::vec(any::<u8>(), 0..=1024),
        domain in DOMAIN,
    ) {
        let (pk, sk) = &pool()[key];
        let signed = sign_detached(&claims, sk, &domain, CryptoConfig::new()).unwrap();
        prop_assert!(
            verify_detached_with_key(&claims, &signed, pk, &domain, CryptoConfig::new()).unwrap()
        );
        let parsed = DetachedSignature::from_json(&signed.to_json().unwrap()).unwrap();
        prop_assert_eq!(parsed, signed);
    }

    #[test]
    fn prop_detached_rejects_modified_claims(
        key in 0..POOL_SIZE,
        claims in prop::collection::vec(any::<u8>(), 1..=1024),
        position in any::<prop::sample::Index>(),
        bit in 0u8..8,
        domain in DOMAIN,
    ) {
        let (pk, sk) = &pool()[key];
        let signed = sign_detached(&claims, sk, &domain, CryptoConfig::new()).unwrap();
        let mut modified = claims.clone();
        modified[position.index(claims.len())] ^= 1 << bit;
        prop_assert!(
            !verify_detached_with_key(&modified, &signed, pk, &domain, CryptoConfig::new())
                .unwrap()
        );
    }

    #[test]
    fn prop_detached_rejects_other_domain(
        key in 0..POOL_SIZE,
        claims in prop::collection::vec(any::<u8>(), 0..=256),
        domain in DOMAIN,
        other in DOMAIN,
    ) {
        prop_assume!(domain != other);
        let (pk, sk) = &pool()[key];
        let mut signed = sign_detached(&claims, sk, &domain, CryptoConfig::new()).unwrap();
        prop_assert!(
            !verify_detached_with_key(&claims, &signed, pk, &other, CryptoConfig::new()).unwrap()
        );
        // Relabelling the record does not help: the domain is in the signed transcript.
        signed.domain = other.clone();
        prop_assert!(
            !verify_detached_with_key(&claims, &signed, pk, &other, CryptoConfig::new()).unwrap()
        );
    }

    #[test]
    fn prop_detached_rejects_other_key(
        key in 0..POOL_SIZE,
        other in 0..POOL_SIZE,
        claims in prop::collection::vec(any::<u8>(), 0..=256),
        domain in DOMAIN,
    ) {
        prop_assume!(key != other);
        let (_, sk) = &pool()[key];
        let (other_pk, _) = &pool()[other];
        let signed = sign_detached(&claims, sk, &domain, CryptoConfig::new()).unwrap();
        prop_assert!(
            !verify_detached_with_key(&claims, &signed, other_pk, &domain, CryptoConfig::new())
                .unwrap()
        );
    }

    #[test]
    fn prop_detached_from_json_never_panics(json in "\\PC{0,512}") {
        let _ = DetachedSignature::from_json(&json);
    }
}
