//! Property-based tests for hybrid KEM (ML-KEM-768 + X25519)
//!
//! Tests roundtrip, key independence, and wrong-key rejection using proptest.

#![allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use arc_hybrid::kem_hybrid::{decapsulate, encapsulate, generate_keypair};
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Hybrid KEM roundtrip: encapsulate then decapsulate recovers same shared secret.
    #[test]
    fn kem_roundtrip(_seed in any::<u64>()) {
        let mut rng = rand::thread_rng();
        let (pk, sk) = generate_keypair(&mut rng).unwrap();
        let encapsulated = encapsulate(&mut rng, &pk).unwrap();
        let decapsulated = decapsulate(&sk, &encapsulated).unwrap();

        // Shared secrets must match
        prop_assert_eq!(
            encapsulated.shared_secret.as_slice(),
            decapsulated.as_slice(),
            "Roundtrip shared secrets must match"
        );
        // Shared secret must be 64 bytes (32 ML-KEM + 32 X25519 via HKDF)
        prop_assert_eq!(decapsulated.len(), 64);
    }

    /// Different keypairs produce different encapsulated secrets.
    #[test]
    fn kem_key_independence(_seed in any::<u64>()) {
        let mut rng = rand::thread_rng();
        let (pk1, _sk1) = generate_keypair(&mut rng).unwrap();
        let (pk2, _sk2) = generate_keypair(&mut rng).unwrap();

        let enc1 = encapsulate(&mut rng, &pk1).unwrap();
        let enc2 = encapsulate(&mut rng, &pk2).unwrap();

        // Different keypairs should produce different shared secrets
        // (with overwhelming probability)
        prop_assert_ne!(
            enc1.shared_secret.as_slice(),
            enc2.shared_secret.as_slice(),
            "Different keypairs should produce different shared secrets"
        );
    }

    /// Wrong secret key cannot recover the correct shared secret.
    #[test]
    fn kem_wrong_key_rejection(_seed in any::<u64>()) {
        let mut rng = rand::thread_rng();
        let (pk1, _sk1) = generate_keypair(&mut rng).unwrap();
        let (_pk2, sk2) = generate_keypair(&mut rng).unwrap();

        let enc = encapsulate(&mut rng, &pk1).unwrap();
        // Decapsulating with wrong SK may error or produce a different secret
        if let Ok(wrong_secret) = decapsulate(&sk2, &enc) {
            prop_assert_ne!(
                enc.shared_secret.as_slice(),
                wrong_secret.as_slice(),
                "Wrong SK must not recover the correct shared secret"
            );
        }
        // Error is also acceptable — wrong key rejected
    }

    /// Multiple encapsulations with the same public key produce different ciphertexts.
    #[test]
    fn kem_encapsulation_uniqueness(_seed in any::<u64>()) {
        let mut rng = rand::thread_rng();
        let (pk, sk) = generate_keypair(&mut rng).unwrap();

        let enc1 = encapsulate(&mut rng, &pk).unwrap();
        let enc2 = encapsulate(&mut rng, &pk).unwrap();

        // Different encapsulations must produce different ciphertexts
        prop_assert_ne!(
            enc1.ml_kem_ct.as_slice(), enc2.ml_kem_ct.as_slice(),
            "Different encapsulations should produce different ML-KEM ciphertexts"
        );

        // Both must still roundtrip correctly
        let dec1 = decapsulate(&sk, &enc1).unwrap();
        let dec2 = decapsulate(&sk, &enc2).unwrap();
        prop_assert_eq!(dec1.as_slice(), enc1.shared_secret.as_slice());
        prop_assert_eq!(dec2.as_slice(), enc2.shared_secret.as_slice());
    }

    /// Key sizes match FIPS 203 / X25519 specifications.
    #[test]
    fn kem_key_sizes(_seed in any::<u64>()) {
        let mut rng = rand::thread_rng();
        let (pk, _sk) = generate_keypair(&mut rng).unwrap();

        // ML-KEM-768 public key: 1184 bytes
        prop_assert_eq!(pk.ml_kem_pk.len(), 1184);
        // X25519 public key: 32 bytes
        prop_assert_eq!(pk.ecdh_pk.len(), 32);

        let enc = encapsulate(&mut rng, &pk).unwrap();
        // ML-KEM-768 ciphertext: 1088 bytes
        prop_assert_eq!(enc.ml_kem_ct.len(), 1088);
        // Ephemeral X25519 public key: 32 bytes
        prop_assert_eq!(enc.ecdh_pk.len(), 32);
        // Shared secret: 64 bytes
        prop_assert_eq!(enc.shared_secret.len(), 64);
    }
}
