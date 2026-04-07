//! Property-based tests for standalone PQ signatures (ML-DSA, SLH-DSA, FN-DSA).
//!
//! Tests roundtrip (sign → verify → true), wrong-message rejection,
//! and wrong-key rejection for each algorithm.  SLH-DSA uses Shake128s
//! (the fastest parameter set); FN-DSA uses Level512.

#![allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use latticearc::primitives::sig::fndsa::{FnDsaSecurityLevel, KeyPair as FnDsaKeyPair};
use latticearc::primitives::sig::ml_dsa::{MlDsaParameterSet, generate_keypair, sign, verify};
use latticearc::primitives::sig::slh_dsa::{SigningKey as SlhSigningKey, SlhDsaSecurityLevel};
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    // =========================================================================
    // ML-DSA-65
    // =========================================================================

    /// ML-DSA-65: signing then verifying must always succeed.
    #[test]
    fn ml_dsa_65_roundtrip(message in prop::collection::vec(any::<u8>(), 0..4096)) {
        let (pk, sk) = generate_keypair(MlDsaParameterSet::MlDsa65).unwrap();
        let sig = sign(&sk, &message, &[]).unwrap();
        let valid = verify(&pk, &message, &sig, &[]).unwrap();
        prop_assert!(valid, "ML-DSA-65 roundtrip must always verify");
    }

    /// ML-DSA-65: a signature on msg1 must not verify for msg2.
    #[test]
    fn ml_dsa_65_wrong_message(
        msg1 in prop::collection::vec(any::<u8>(), 1..1024),
        msg2 in prop::collection::vec(any::<u8>(), 1..1024),
    ) {
        prop_assume!(msg1 != msg2);
        let (pk, sk) = generate_keypair(MlDsaParameterSet::MlDsa65).unwrap();
        let sig = sign(&sk, &msg1, &[]).unwrap();
        if let Ok(valid) = verify(&pk, &msg2, &sig, &[]) {
            prop_assert!(!valid, "Wrong message must not verify for ML-DSA-65");
        }
        // A verification error is also acceptable
    }

    /// ML-DSA-65: a signature verified with the wrong public key must fail.
    #[test]
    fn ml_dsa_65_wrong_key(message in prop::collection::vec(any::<u8>(), 1..256)) {
        let (_pk1, sk1) = generate_keypair(MlDsaParameterSet::MlDsa65).unwrap();
        let (pk2, _sk2) = generate_keypair(MlDsaParameterSet::MlDsa65).unwrap();
        let sig = sign(&sk1, &message, &[]).unwrap();
        if let Ok(valid) = verify(&pk2, &message, &sig, &[]) {
            prop_assert!(!valid, "Wrong public key must not verify ML-DSA-65 signature");
        }
    }

    // =========================================================================
    // SLH-DSA-Shake128s  (fastest SLH-DSA parameter set)
    // =========================================================================

    /// SLH-DSA-Shake128s: signing then verifying must always succeed.
    #[test]
    fn slh_dsa_shake128s_roundtrip(message in prop::collection::vec(any::<u8>(), 0..1024)) {
        let (sk, vk) = SlhSigningKey::generate(SlhDsaSecurityLevel::Shake128s).unwrap();
        let sig = sk.sign(&message, None).unwrap();
        let valid = vk.verify(&message, &sig, None).unwrap();
        prop_assert!(valid, "SLH-DSA-Shake128s roundtrip must always verify");
    }

    /// SLH-DSA-Shake128s: a signature on msg1 must not verify for msg2.
    #[test]
    fn slh_dsa_shake128s_wrong_message(
        msg1 in prop::collection::vec(any::<u8>(), 1..256),
        msg2 in prop::collection::vec(any::<u8>(), 1..256),
    ) {
        prop_assume!(msg1 != msg2);
        let (sk, vk) = SlhSigningKey::generate(SlhDsaSecurityLevel::Shake128s).unwrap();
        let sig = sk.sign(&msg1, None).unwrap();
        if let Ok(valid) = vk.verify(&msg2, &sig, None) {
            prop_assert!(!valid, "Wrong message must not verify for SLH-DSA-Shake128s");
        }
    }

    /// SLH-DSA-Shake128s: a signature verified with the wrong public key must fail.
    #[test]
    fn slh_dsa_shake128s_wrong_key(message in prop::collection::vec(any::<u8>(), 1..256)) {
        let (sk1, _vk1) = SlhSigningKey::generate(SlhDsaSecurityLevel::Shake128s).unwrap();
        let (_sk2, vk2) = SlhSigningKey::generate(SlhDsaSecurityLevel::Shake128s).unwrap();
        let sig = sk1.sign(&message, None).unwrap();
        if let Ok(valid) = vk2.verify(&message, &sig, None) {
            prop_assert!(!valid, "Wrong public key must not verify SLH-DSA-Shake128s signature");
        }
    }

    // =========================================================================
    // FN-DSA-512  (Level512, ~128-bit security)
    // =========================================================================

    /// FN-DSA-512: signing then verifying must always succeed.
    #[test]
    fn fn_dsa_512_roundtrip(message in prop::collection::vec(any::<u8>(), 0..4096)) {
        let mut kp = FnDsaKeyPair::generate(FnDsaSecurityLevel::Level512).unwrap();
        let sig = kp.sign(&message).unwrap();
        let valid = kp.verifying_key().verify(&message, &sig).unwrap();
        prop_assert!(valid, "FN-DSA-512 roundtrip must always verify");
    }

    /// FN-DSA-512: a signature on msg1 must not verify for msg2.
    #[test]
    fn fn_dsa_512_wrong_message(
        msg1 in prop::collection::vec(any::<u8>(), 1..512),
        msg2 in prop::collection::vec(any::<u8>(), 1..512),
    ) {
        prop_assume!(msg1 != msg2);
        let mut kp = FnDsaKeyPair::generate(FnDsaSecurityLevel::Level512).unwrap();
        let sig = kp.sign(&msg1).unwrap();
        if let Ok(valid) = kp.verifying_key().verify(&msg2, &sig) {
            prop_assert!(!valid, "Wrong message must not verify for FN-DSA-512");
        }
    }

    /// FN-DSA-512: a signature verified with the wrong public key must fail.
    #[test]
    fn fn_dsa_512_wrong_key(message in prop::collection::vec(any::<u8>(), 1..256)) {
        let mut kp1 = FnDsaKeyPair::generate(FnDsaSecurityLevel::Level512).unwrap();
        let kp2 = FnDsaKeyPair::generate(FnDsaSecurityLevel::Level512).unwrap();
        let sig = kp1.sign(&message).unwrap();
        if let Ok(valid) = kp2.verifying_key().verify(&message, &sig) {
            prop_assert!(!valid, "Wrong public key must not verify FN-DSA-512 signature");
        }
    }
}
