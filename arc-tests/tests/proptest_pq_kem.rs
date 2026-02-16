//! Property-based tests for pure PQ KEM (ML-KEM) through the arc-core API.
//!
//! Tests ML-KEM encapsulation roundtrip at all 3 parameter sets,
//! shared secret length, and key/ciphertext size validation.

#![allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use arc_primitives::kem::ml_kem::{MlKem, MlKemPublicKey, MlKemSecurityLevel};
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// ML-KEM-768 roundtrip: encapsulate then decapsulate recovers same shared secret.
    #[test]
    fn ml_kem_768_roundtrip(_seed in any::<u64>()) {
        let mut rng = rand::thread_rng();
        let level = MlKemSecurityLevel::MlKem768;

        let keypair = MlKem::generate_decapsulation_keypair(level).unwrap();
        let pk_bytes = keypair.public_key_bytes().to_vec();
        let pk = MlKemPublicKey::new(level, pk_bytes).unwrap();

        let (ss_enc, ct) = MlKem::encapsulate(&mut rng, &pk).unwrap();
        let ss_dec = keypair.decapsulate(&ct).unwrap();

        prop_assert_eq!(
            ss_enc.as_bytes(),
            ss_dec.as_bytes(),
            "ML-KEM-768 roundtrip shared secrets must match"
        );
        prop_assert_eq!(ss_enc.as_bytes().len(), 32, "Shared secret must be 32 bytes");
    }

    /// ML-KEM-512 roundtrip.
    #[test]
    fn ml_kem_512_roundtrip(_seed in any::<u64>()) {
        let mut rng = rand::thread_rng();
        let level = MlKemSecurityLevel::MlKem512;

        let keypair = MlKem::generate_decapsulation_keypair(level).unwrap();
        let pk_bytes = keypair.public_key_bytes().to_vec();
        let pk = MlKemPublicKey::new(level, pk_bytes).unwrap();

        let (ss_enc, ct) = MlKem::encapsulate(&mut rng, &pk).unwrap();
        let ss_dec = keypair.decapsulate(&ct).unwrap();

        prop_assert_eq!(ss_enc.as_bytes(), ss_dec.as_bytes());
        prop_assert_eq!(ss_enc.as_bytes().len(), 32);
    }

    /// ML-KEM-1024 roundtrip.
    #[test]
    fn ml_kem_1024_roundtrip(_seed in any::<u64>()) {
        let mut rng = rand::thread_rng();
        let level = MlKemSecurityLevel::MlKem1024;

        let keypair = MlKem::generate_decapsulation_keypair(level).unwrap();
        let pk_bytes = keypair.public_key_bytes().to_vec();
        let pk = MlKemPublicKey::new(level, pk_bytes).unwrap();

        let (ss_enc, ct) = MlKem::encapsulate(&mut rng, &pk).unwrap();
        let ss_dec = keypair.decapsulate(&ct).unwrap();

        prop_assert_eq!(ss_enc.as_bytes(), ss_dec.as_bytes());
        prop_assert_eq!(ss_enc.as_bytes().len(), 32);
    }

    /// ML-KEM-768 key sizes match FIPS 203 spec.
    #[test]
    fn ml_kem_768_key_sizes(_seed in any::<u64>()) {
        let level = MlKemSecurityLevel::MlKem768;
        let keypair = MlKem::generate_decapsulation_keypair(level).unwrap();

        // ML-KEM-768: pk=1184, ct=1088
        prop_assert_eq!(keypair.public_key_bytes().len(), 1184, "ML-KEM-768 public key");
    }

    /// ML-KEM-512 key sizes match FIPS 203 spec.
    #[test]
    fn ml_kem_512_key_sizes(_seed in any::<u64>()) {
        let level = MlKemSecurityLevel::MlKem512;
        let keypair = MlKem::generate_decapsulation_keypair(level).unwrap();

        // ML-KEM-512: pk=800
        prop_assert_eq!(keypair.public_key_bytes().len(), 800, "ML-KEM-512 public key");
    }

    /// ML-KEM-1024 key sizes match FIPS 203 spec.
    #[test]
    fn ml_kem_1024_key_sizes(_seed in any::<u64>()) {
        let level = MlKemSecurityLevel::MlKem1024;
        let keypair = MlKem::generate_decapsulation_keypair(level).unwrap();

        // ML-KEM-1024: pk=1568
        prop_assert_eq!(keypair.public_key_bytes().len(), 1568, "ML-KEM-1024 public key");
    }

    /// ML-KEM ciphertext sizes match FIPS 203 spec.
    #[test]
    fn ml_kem_ciphertext_sizes(_seed in any::<u64>()) {
        let mut rng = rand::thread_rng();

        // ML-KEM-512: ct=768
        let kp512 = MlKem::generate_decapsulation_keypair(MlKemSecurityLevel::MlKem512).unwrap();
        let pk512 = MlKemPublicKey::new(MlKemSecurityLevel::MlKem512, kp512.public_key_bytes().to_vec()).unwrap();
        let (_, ct512) = MlKem::encapsulate(&mut rng, &pk512).unwrap();
        prop_assert_eq!(ct512.as_bytes().len(), 768, "ML-KEM-512 ciphertext");

        // ML-KEM-768: ct=1088
        let kp768 = MlKem::generate_decapsulation_keypair(MlKemSecurityLevel::MlKem768).unwrap();
        let pk768 = MlKemPublicKey::new(MlKemSecurityLevel::MlKem768, kp768.public_key_bytes().to_vec()).unwrap();
        let (_, ct768) = MlKem::encapsulate(&mut rng, &pk768).unwrap();
        prop_assert_eq!(ct768.as_bytes().len(), 1088, "ML-KEM-768 ciphertext");

        // ML-KEM-1024: ct=1568
        let kp1024 = MlKem::generate_decapsulation_keypair(MlKemSecurityLevel::MlKem1024).unwrap();
        let pk1024 = MlKemPublicKey::new(MlKemSecurityLevel::MlKem1024, kp1024.public_key_bytes().to_vec()).unwrap();
        let (_, ct1024) = MlKem::encapsulate(&mut rng, &pk1024).unwrap();
        prop_assert_eq!(ct1024.as_bytes().len(), 1568, "ML-KEM-1024 ciphertext");
    }

    /// Different encapsulations with same public key produce different shared secrets.
    #[test]
    fn ml_kem_encapsulation_uniqueness(_seed in any::<u64>()) {
        let mut rng = rand::thread_rng();
        let level = MlKemSecurityLevel::MlKem768;

        let keypair = MlKem::generate_decapsulation_keypair(level).unwrap();
        let pk_bytes = keypair.public_key_bytes().to_vec();
        let pk = MlKemPublicKey::new(level, pk_bytes).unwrap();

        let (ss1, _ct1) = MlKem::encapsulate(&mut rng, &pk).unwrap();
        let (ss2, _ct2) = MlKem::encapsulate(&mut rng, &pk).unwrap();

        prop_assert_ne!(
            ss1.as_bytes(), ss2.as_bytes(),
            "Different encapsulations must produce different shared secrets"
        );
    }
}
