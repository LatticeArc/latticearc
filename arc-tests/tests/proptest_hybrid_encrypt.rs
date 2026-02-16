//! Property-based tests for hybrid encryption (ML-KEM-768 + X25519 + AES-256-GCM)
//!
//! Tests roundtrip, variable-size plaintext, non-malleability, key independence,
//! and AAD integrity.

#![allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use arc_hybrid::encrypt_hybrid::{HybridEncryptionContext, decrypt_hybrid, encrypt_hybrid};
use arc_hybrid::kem_hybrid::generate_keypair;
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Hybrid encryption roundtrip: encrypt then decrypt recovers original plaintext.
    #[test]
    fn encrypt_roundtrip(plaintext in prop::collection::vec(any::<u8>(), 0..1024)) {
        let mut rng = rand::thread_rng();
        let (pk, sk) = generate_keypair(&mut rng).unwrap();

        let ciphertext = encrypt_hybrid(&mut rng, &pk, &plaintext, None).unwrap();
        let decrypted = decrypt_hybrid(&sk, &ciphertext, None).unwrap();

        prop_assert_eq!(&decrypted, &plaintext, "Roundtrip must recover original plaintext");
    }

    /// Larger plaintext sizes (up to 64KB).
    #[test]
    fn encrypt_large_plaintext(
        plaintext in prop::collection::vec(any::<u8>(), 1024..65536)
    ) {
        let mut rng = rand::thread_rng();
        let (pk, sk) = generate_keypair(&mut rng).unwrap();

        let ciphertext = encrypt_hybrid(&mut rng, &pk, &plaintext, None).unwrap();
        let decrypted = decrypt_hybrid(&sk, &ciphertext, None).unwrap();

        prop_assert_eq!(&decrypted, &plaintext);
    }

    /// Non-malleability: flipping a bit in the symmetric ciphertext causes decryption failure.
    #[test]
    fn encrypt_non_malleability(
        plaintext in prop::collection::vec(any::<u8>(), 1..512),
        bit_pos in 0usize..8
    ) {
        let mut rng = rand::thread_rng();
        let (pk, sk) = generate_keypair(&mut rng).unwrap();

        let mut ciphertext = encrypt_hybrid(&mut rng, &pk, &plaintext, None).unwrap();

        // Flip a bit in the symmetric ciphertext
        if !ciphertext.symmetric_ciphertext.is_empty() {
            let byte_idx = 0; // flip first byte
            ciphertext.symmetric_ciphertext[byte_idx] ^= 1u8 << (bit_pos % 8);

            let result = decrypt_hybrid(&sk, &ciphertext, None);
            prop_assert!(result.is_err(), "Tampered ciphertext must fail to decrypt");
        }
    }

    /// Key independence: different keypairs cannot decrypt each other's ciphertexts.
    #[test]
    fn encrypt_key_independence(
        plaintext in prop::collection::vec(any::<u8>(), 1..256)
    ) {
        let mut rng = rand::thread_rng();
        let (pk1, _sk1) = generate_keypair(&mut rng).unwrap();
        let (_pk2, sk2) = generate_keypair(&mut rng).unwrap();

        let ciphertext = encrypt_hybrid(&mut rng, &pk1, &plaintext, None).unwrap();

        // Wrong key should fail to decrypt
        if let Ok(decrypted) = decrypt_hybrid(&sk2, &ciphertext, None) {
            // If it somehow decrypts, the plaintext must differ
            prop_assert_ne!(
                &decrypted, &plaintext,
                "Wrong key must not recover correct plaintext"
            );
        }
        // Error is expected — wrong key cannot decrypt
    }

    /// AAD integrity: mismatched AAD causes decryption failure.
    #[test]
    fn encrypt_aad_integrity(
        plaintext in prop::collection::vec(any::<u8>(), 1..256),
        aad1 in prop::collection::vec(any::<u8>(), 1..64),
        aad2 in prop::collection::vec(any::<u8>(), 1..64),
    ) {
        prop_assume!(aad1 != aad2);

        let mut rng = rand::thread_rng();
        let (pk, sk) = generate_keypair(&mut rng).unwrap();

        let ctx1 = HybridEncryptionContext {
            info: b"LatticeArc-Hybrid-Encryption-v1".to_vec(),
            aad: aad1,
        };
        let ctx2 = HybridEncryptionContext {
            info: b"LatticeArc-Hybrid-Encryption-v1".to_vec(),
            aad: aad2,
        };

        let ciphertext = encrypt_hybrid(&mut rng, &pk, &plaintext, Some(&ctx1)).unwrap();

        // Decrypting with different AAD should fail
        let result = decrypt_hybrid(&sk, &ciphertext, Some(&ctx2));
        prop_assert!(result.is_err(), "Mismatched AAD must cause decryption failure");
    }

    /// Empty plaintext roundtrips correctly.
    #[test]
    fn encrypt_empty_plaintext(_seed in any::<u64>()) {
        let mut rng = rand::thread_rng();
        let (pk, sk) = generate_keypair(&mut rng).unwrap();

        let ciphertext = encrypt_hybrid(&mut rng, &pk, &[], None).unwrap();
        let decrypted = decrypt_hybrid(&sk, &ciphertext, None).unwrap();

        prop_assert!(decrypted.is_empty(), "Empty plaintext must roundtrip to empty");
    }
}
