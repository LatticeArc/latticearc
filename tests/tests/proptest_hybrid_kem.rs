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

use latticearc::hybrid::kem_hybrid::{decapsulate, encapsulate, generate_keypair};
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Hybrid KEM roundtrip: encapsulate then decapsulate recovers same shared secret.
    #[test]
    fn kem_roundtrip(_seed in any::<u64>()) {
        let (pk, sk) = generate_keypair().unwrap();
        let encapsulated = encapsulate(&pk).unwrap();
        let decapsulated = decapsulate(&sk, &encapsulated).unwrap();

        // Shared secrets must match
        prop_assert_eq!(
            encapsulated.expose_secret(),
            decapsulated.expose_secret(),
            "Roundtrip shared secrets must match"
        );
        // Shared secret must be 64 bytes (32 ML-KEM + 32 X25519 via HKDF)
        prop_assert_eq!(decapsulated.len(), 64);
    }

    /// Different keypairs produce different encapsulated secrets.
    #[test]
    fn kem_key_independence(_seed in any::<u64>()) {
        let (pk1, _sk1) = generate_keypair().unwrap();
        let (pk2, _sk2) = generate_keypair().unwrap();

        let enc1 = encapsulate(&pk1).unwrap();
        let enc2 = encapsulate(&pk2).unwrap();

        // Different keypairs should produce different shared secrets
        // (with overwhelming probability)
        prop_assert_ne!(
            enc1.expose_secret(),
            enc2.expose_secret(),
            "Different keypairs should produce different shared secrets"
        );
    }

    /// Wrong secret key cannot recover the correct shared secret.
    #[test]
    fn kem_wrong_key_rejection(_seed in any::<u64>()) {
        let (pk1, _sk1) = generate_keypair().unwrap();
        let (_pk2, sk2) = generate_keypair().unwrap();

        let enc = encapsulate(&pk1).unwrap();
        // Decapsulating with wrong SK may error or produce a different secret
        if let Ok(wrong_secret) = decapsulate(&sk2, &enc) {
            prop_assert_ne!(
                enc.expose_secret(),
                wrong_secret.expose_secret(),
                "Wrong SK must not recover the correct shared secret"
            );
        }
        // Error is also acceptable — wrong key rejected
    }

    /// Multiple encapsulations with the same public key produce different ciphertexts.
    #[test]
    fn kem_encapsulation_uniqueness(_seed in any::<u64>()) {
        let (pk, sk) = generate_keypair().unwrap();

        let enc1 = encapsulate(&pk).unwrap();
        let enc2 = encapsulate(&pk).unwrap();

        // Different encapsulations must produce different ciphertexts
        prop_assert_ne!(
            enc1.ml_kem_ct(), enc2.ml_kem_ct(),
            "Different encapsulations should produce different ML-KEM ciphertexts"
        );

        // Both must still roundtrip correctly
        let dec1 = decapsulate(&sk, &enc1).unwrap();
        let dec2 = decapsulate(&sk, &enc2).unwrap();
        prop_assert_eq!(dec1.expose_secret(), enc1.expose_secret());
        prop_assert_eq!(dec2.expose_secret(), enc2.expose_secret());
    }

    /// Key sizes match FIPS 203 / X25519 specifications.
    #[test]
    fn kem_key_sizes(_seed in any::<u64>()) {
        let (pk, _sk) = generate_keypair().unwrap();

        // ML-KEM-768 public key: 1184 bytes
        prop_assert_eq!(pk.ml_kem_pk().len(), 1184);
        // X25519 public key: 32 bytes
        prop_assert_eq!(pk.ecdh_pk().len(), 32);

        let enc = encapsulate(&pk).unwrap();
        // ML-KEM-768 ciphertext: 1088 bytes
        prop_assert_eq!(enc.ml_kem_ct().len(), 1088);
        // Ephemeral X25519 public key: 32 bytes
        prop_assert_eq!(enc.ecdh_pk().len(), 32);
        // Shared secret: 64 bytes
        prop_assert_eq!(enc.expose_secret().len(), 64);
    }
}
