//! Property-based tests for hybrid signatures (ML-DSA-65 + Ed25519)
//!
//! Tests roundtrip, wrong-message rejection, wrong-key rejection,
//! variable message sizes, and signature determinism.

#![allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use arc_hybrid::sig_hybrid::{generate_keypair, sign, verify};
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Sign then verify succeeds for any message.
    #[test]
    fn sig_roundtrip(message in prop::collection::vec(any::<u8>(), 0..1024)) {
        let mut rng = rand::thread_rng();
        let (pk, sk) = generate_keypair(&mut rng).unwrap();

        let signature = sign(&sk, &message).unwrap();
        let valid = verify(&pk, &message, &signature).unwrap();

        prop_assert!(valid, "Valid signature must verify");
    }

    /// Signature on large messages (up to 64KB).
    #[test]
    fn sig_large_message(message in prop::collection::vec(any::<u8>(), 1024..65536)) {
        let mut rng = rand::thread_rng();
        let (pk, sk) = generate_keypair(&mut rng).unwrap();

        let signature = sign(&sk, &message).unwrap();
        let valid = verify(&pk, &message, &signature).unwrap();

        prop_assert!(valid);
    }

    /// Verification fails for a different message.
    #[test]
    fn sig_wrong_message(
        message1 in prop::collection::vec(any::<u8>(), 1..512),
        message2 in prop::collection::vec(any::<u8>(), 1..512),
    ) {
        prop_assume!(message1 != message2);

        let mut rng = rand::thread_rng();
        let (pk, sk) = generate_keypair(&mut rng).unwrap();

        let signature = sign(&sk, &message1).unwrap();
        if let Ok(valid) = verify(&pk, &message2, &signature) {
            prop_assert!(!valid, "Wrong message must not verify");
        }
        // Verification error is also expected
    }

    /// Verification fails with wrong public key.
    #[test]
    fn sig_wrong_key(message in prop::collection::vec(any::<u8>(), 1..256)) {
        let mut rng = rand::thread_rng();
        let (_pk1, sk1) = generate_keypair(&mut rng).unwrap();
        let (pk2, _sk2) = generate_keypair(&mut rng).unwrap();

        let signature = sign(&sk1, &message).unwrap();
        if let Ok(valid) = verify(&pk2, &message, &signature) {
            prop_assert!(!valid, "Wrong public key must not verify");
        }
        // Verification error is also expected
    }

    /// Ed25519 component is deterministic: same (sk, message) -> same Ed25519 signature.
    /// ML-DSA-65 (fips204) uses hedged/randomized signing per FIPS 204, so the
    /// ML-DSA component differs each time. Both must still verify.
    #[test]
    fn sig_ed25519_determinism(message in prop::collection::vec(any::<u8>(), 0..256)) {
        let mut rng = rand::thread_rng();
        let (pk, sk) = generate_keypair(&mut rng).unwrap();

        let sig1 = sign(&sk, &message).unwrap();
        let sig2 = sign(&sk, &message).unwrap();

        // Ed25519 is deterministic (RFC 8032)
        prop_assert_eq!(&sig1.ed25519_sig, &sig2.ed25519_sig,
            "Ed25519 signatures must be deterministic");

        // ML-DSA is randomized — both must still verify
        prop_assert!(verify(&pk, &message, &sig1).unwrap());
        prop_assert!(verify(&pk, &message, &sig2).unwrap());
    }

    /// Empty message can be signed and verified.
    #[test]
    fn sig_empty_message(_seed in any::<u64>()) {
        let mut rng = rand::thread_rng();
        let (pk, sk) = generate_keypair(&mut rng).unwrap();

        let signature = sign(&sk, &[]).unwrap();
        let valid = verify(&pk, &[], &signature).unwrap();

        prop_assert!(valid, "Empty message signature must verify");
    }

    /// Signature sizes match spec (ML-DSA-65 + Ed25519).
    #[test]
    fn sig_sizes(message in prop::collection::vec(any::<u8>(), 0..256)) {
        let mut rng = rand::thread_rng();
        let (pk, sk) = generate_keypair(&mut rng).unwrap();

        // Key sizes
        prop_assert_eq!(pk.ml_dsa_pk.len(), 1952, "ML-DSA-65 public key");
        prop_assert_eq!(pk.ed25519_pk.len(), 32, "Ed25519 public key");

        let signature = sign(&sk, &message).unwrap();
        // ML-DSA-65 signature: 3309 bytes (fips204 crate)
        prop_assert_eq!(signature.ml_dsa_sig.len(), 3309, "ML-DSA-65 signature");
        prop_assert_eq!(signature.ed25519_sig.len(), 64, "Ed25519 signature");
    }
}
