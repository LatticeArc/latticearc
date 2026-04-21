//! Property-based tests for standalone PQ signatures (ML-DSA, SLH-DSA, FN-DSA).
//!
//! Tests roundtrip (sign → verify → true), wrong-message rejection,
//! and wrong-key rejection for each algorithm.  SLH-DSA uses Shake128s
//! (smallest signature at ~128-bit security); FN-DSA uses Level512.
//!
//! # Key pooling
//!
//! Each case previously generated a fresh keypair, which made FN-DSA tests
//! dominate wall-clock time (FN-DSA keygen is ~2-3 s in release mode on
//! modern silicon; 1024 keygens × 3 s ≈ 50 min). We instead generate a
//! fixed pool of [`POOL_SIZE`] keypairs per algorithm on first use, and
//! each proptest case selects one by index. This preserves:
//!
//! - **256 cases per property** — full message-variation coverage, unchanged.
//! - **16 distinct keys per algorithm** — still exercises keygen randomness
//!   and catches key-dependent bugs in sign/verify.
//! - **Cross product** of keys × messages is ~16× broader than before
//!   (each of 16 keys sees ~16 different messages on average, vs. the prior
//!   "one key, one message per case" pattern that produced 256 unrelated
//!   single-point samples).
//!
//! Total keygen work drops from ~1024 to ~48 (3 algos × 16), amortized
//! across the whole test file via `OnceLock`.

#![allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use latticearc::primitives::sig::fndsa::{
    FnDsaSecurityLevel, KeyPair as FnDsaKeyPair, VerifyingKey as FnDsaVerifyingKey,
};
use latticearc::primitives::sig::ml_dsa::{
    MlDsaParameterSet, MlDsaPublicKey, MlDsaSecretKey, generate_keypair,
};
use latticearc::primitives::sig::slh_dsa::{
    SigningKey as SlhSigningKey, SlhDsaSecurityLevel, VerifyingKey as SlhVerifyingKey,
};
use proptest::prelude::*;
use std::sync::{Mutex, OnceLock};

/// Number of distinct keypairs generated per algorithm and shared across
/// all proptest cases. See module docstring for rationale.
const POOL_SIZE: usize = 16;

fn ml_dsa_65_pool() -> &'static [(MlDsaPublicKey, MlDsaSecretKey)] {
    static POOL: OnceLock<Vec<(MlDsaPublicKey, MlDsaSecretKey)>> = OnceLock::new();
    POOL.get_or_init(|| {
        (0..POOL_SIZE).map(|_| generate_keypair(MlDsaParameterSet::MlDsa65).unwrap()).collect()
    })
}

fn slh_dsa_shake128s_pool() -> &'static [(SlhSigningKey, SlhVerifyingKey)] {
    static POOL: OnceLock<Vec<(SlhSigningKey, SlhVerifyingKey)>> = OnceLock::new();
    POOL.get_or_init(|| {
        (0..POOL_SIZE)
            .map(|_| SlhSigningKey::generate(SlhDsaSecurityLevel::Shake128s).unwrap())
            .collect()
    })
}

/// FN-DSA `sign` takes `&mut self` (the upstream `fn-dsa` crate mutates
/// internal state during signing), so pool entries are wrapped in `Mutex`.
/// There is no real contention because proptest runs cases sequentially
/// within a single test.
fn fn_dsa_512_pool() -> &'static [Mutex<FnDsaKeyPair>] {
    static POOL: OnceLock<Vec<Mutex<FnDsaKeyPair>>> = OnceLock::new();
    POOL.get_or_init(|| {
        (0..POOL_SIZE)
            .map(|_| Mutex::new(FnDsaKeyPair::generate(FnDsaSecurityLevel::Level512).unwrap()))
            .collect()
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    // =========================================================================
    // ML-DSA-65
    // =========================================================================

    /// ML-DSA-65: signing then verifying must always succeed.
    #[test]
    fn ml_dsa_65_roundtrip(
        message in prop::collection::vec(any::<u8>(), 0..4096),
        key_idx in 0usize..POOL_SIZE,
    ) {
        let (pk, sk) = &ml_dsa_65_pool()[key_idx];
        let sig = sk.sign(&message, &[]).unwrap();
        let valid = pk.verify(&message, &sig, &[]).unwrap();
        prop_assert!(valid, "ML-DSA-65 roundtrip must always verify");
    }

    /// ML-DSA-65: a signature on msg1 must not verify for msg2.
    #[test]
    fn ml_dsa_65_wrong_message(
        msg1 in prop::collection::vec(any::<u8>(), 1..1024),
        msg2 in prop::collection::vec(any::<u8>(), 1..1024),
        key_idx in 0usize..POOL_SIZE,
    ) {
        prop_assume!(msg1 != msg2);
        let (pk, sk) = &ml_dsa_65_pool()[key_idx];
        let sig = sk.sign(&msg1, &[]).unwrap();
        if let Ok(valid) = pk.verify(&msg2, &sig, &[]) {
            prop_assert!(!valid, "Wrong message must not verify for ML-DSA-65");
        }
        // A verification error is also acceptable
    }

    /// ML-DSA-65: a signature verified with the wrong public key must fail.
    #[test]
    fn ml_dsa_65_wrong_key(
        message in prop::collection::vec(any::<u8>(), 1..256),
        key1_idx in 0usize..POOL_SIZE,
        key2_idx in 0usize..POOL_SIZE,
    ) {
        prop_assume!(key1_idx != key2_idx);
        let pool = ml_dsa_65_pool();
        let sk1 = &pool[key1_idx].1;
        let pk2 = &pool[key2_idx].0;
        let sig = sk1.sign(&message, &[]).unwrap();
        if let Ok(valid) = pk2.verify(&message, &sig, &[]) {
            prop_assert!(!valid, "Wrong public key must not verify ML-DSA-65 signature");
        }
    }

    // =========================================================================
    // SLH-DSA-Shake128s  (128-bit security, smallest-signature variant)
    // =========================================================================

    /// SLH-DSA-Shake128s: signing then verifying must always succeed.
    #[test]
    fn slh_dsa_shake128s_roundtrip(
        message in prop::collection::vec(any::<u8>(), 0..1024),
        key_idx in 0usize..POOL_SIZE,
    ) {
        let (sk, vk) = &slh_dsa_shake128s_pool()[key_idx];
        let sig = sk.sign(&message, &[]).unwrap();
        let valid = vk.verify(&message, &sig, &[]).unwrap();
        prop_assert!(valid, "SLH-DSA-Shake128s roundtrip must always verify");
    }

    /// SLH-DSA-Shake128s: a signature on msg1 must not verify for msg2.
    #[test]
    fn slh_dsa_shake128s_wrong_message(
        msg1 in prop::collection::vec(any::<u8>(), 1..256),
        msg2 in prop::collection::vec(any::<u8>(), 1..256),
        key_idx in 0usize..POOL_SIZE,
    ) {
        prop_assume!(msg1 != msg2);
        let (sk, vk) = &slh_dsa_shake128s_pool()[key_idx];
        let sig = sk.sign(&msg1, &[]).unwrap();
        if let Ok(valid) = vk.verify(&msg2, &sig, &[]) {
            prop_assert!(!valid, "Wrong message must not verify for SLH-DSA-Shake128s");
        }
    }

    /// SLH-DSA-Shake128s: a signature verified with the wrong public key must fail.
    #[test]
    fn slh_dsa_shake128s_wrong_key(
        message in prop::collection::vec(any::<u8>(), 1..256),
        key1_idx in 0usize..POOL_SIZE,
        key2_idx in 0usize..POOL_SIZE,
    ) {
        prop_assume!(key1_idx != key2_idx);
        let pool = slh_dsa_shake128s_pool();
        let sk1 = &pool[key1_idx].0;
        let vk2 = &pool[key2_idx].1;
        let sig = sk1.sign(&message, &[]).unwrap();
        if let Ok(valid) = vk2.verify(&message, &sig, &[]) {
            prop_assert!(!valid, "Wrong public key must not verify SLH-DSA-Shake128s signature");
        }
    }

    // =========================================================================
    // FN-DSA-512  (Level512, ~128-bit security)
    // =========================================================================

    /// FN-DSA-512: signing then verifying must always succeed.
    #[test]
    fn fn_dsa_512_roundtrip(
        message in prop::collection::vec(any::<u8>(), 0..4096),
        key_idx in 0usize..POOL_SIZE,
    ) {
        let mut kp = fn_dsa_512_pool()[key_idx].lock().unwrap();
        let sig = kp.sign(&message).unwrap();
        let valid = kp.verifying_key().verify(&message, &sig).unwrap();
        prop_assert!(valid, "FN-DSA-512 roundtrip must always verify");
    }

    /// FN-DSA-512: a signature on msg1 must not verify for msg2.
    #[test]
    fn fn_dsa_512_wrong_message(
        msg1 in prop::collection::vec(any::<u8>(), 1..512),
        msg2 in prop::collection::vec(any::<u8>(), 1..512),
        key_idx in 0usize..POOL_SIZE,
    ) {
        prop_assume!(msg1 != msg2);
        let mut kp = fn_dsa_512_pool()[key_idx].lock().unwrap();
        let sig = kp.sign(&msg1).unwrap();
        if let Ok(valid) = kp.verifying_key().verify(&msg2, &sig) {
            prop_assert!(!valid, "Wrong message must not verify for FN-DSA-512");
        }
    }

    /// FN-DSA-512: a signature verified with the wrong public key must fail.
    ///
    /// We borrow key 1's signing key and key 2's verifying key separately
    /// (locking kp1, signing, releasing; then locking kp2 only to extract
    /// the verifying key) to avoid holding two mutex guards simultaneously.
    #[test]
    fn fn_dsa_512_wrong_key(
        message in prop::collection::vec(any::<u8>(), 1..256),
        key1_idx in 0usize..POOL_SIZE,
        key2_idx in 0usize..POOL_SIZE,
    ) {
        prop_assume!(key1_idx != key2_idx);
        let pool = fn_dsa_512_pool();
        let sig = {
            let mut kp1 = pool[key1_idx].lock().unwrap();
            kp1.sign(&message).unwrap()
        };
        let vk2: FnDsaVerifyingKey = {
            let kp2 = pool[key2_idx].lock().unwrap();
            kp2.verifying_key().clone()
        };
        if let Ok(valid) = vk2.verify(&message, &sig) {
            prop_assert!(!valid, "Wrong public key must not verify FN-DSA-512 signature");
        }
    }
}
