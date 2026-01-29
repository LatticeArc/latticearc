//! Property-Based Cryptographic Tests
//!
//! This module contains comprehensive property-based tests using proptest
//! to validate cryptographic invariants across a wide range of inputs.
//!
//! ## Properties Tested
//!
//! - **Roundtrip**: Encrypt then decrypt returns original
//! - **Determinism**: Same inputs produce same outputs (where applicable)
//! - **Key Independence**: Different keys produce different outputs
//! - **Non-Malleability**: Modified ciphertext fails to decrypt
//! - **Length Preservation**: Output lengths are predictable

// JUSTIFICATION: Property-based test code requires these patterns
#![allow(clippy::unwrap_used)] // Proptest requires unwrap in some cases
#![allow(clippy::expect_used)] // Test assertions
#![allow(clippy::arithmetic_side_effects)] // Test index calculations
#![allow(clippy::indexing_slicing)] // Test data manipulation
#![allow(clippy::redundant_clone)] // Proptest data handling

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    // ==========================================================================
    // AES-GCM Property Tests
    // ==========================================================================

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(1000))]

        /// AES-GCM encryption/decryption roundtrip
        #[test]
        fn aes_gcm_roundtrip(
            key in prop::array::uniform32(any::<u8>()),
            nonce in prop::array::uniform12(any::<u8>()),
            plaintext in prop::collection::vec(any::<u8>(), 0..4096),
            aad in prop::collection::vec(any::<u8>(), 0..256)
        ) {
            use aws_lc_rs::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};

            let unbound_key = UnboundKey::new(&AES_256_GCM, &key).unwrap();
            let less_safe_key = LessSafeKey::new(unbound_key);

            // Encrypt
            let nonce_obj = Nonce::assume_unique_for_key(nonce);
            let mut ciphertext = plaintext.clone();
            less_safe_key.seal_in_place_append_tag(
                nonce_obj,
                Aad::from(&aad),
                &mut ciphertext
            ).unwrap();

            // Decrypt
            let unbound_key2 = UnboundKey::new(&AES_256_GCM, &key).unwrap();
            let less_safe_key2 = LessSafeKey::new(unbound_key2);
            let nonce_obj2 = Nonce::assume_unique_for_key(nonce);

            let decrypted = less_safe_key2.open_in_place(
                nonce_obj2,
                Aad::from(&aad),
                &mut ciphertext
            ).unwrap();

            prop_assert_eq!(decrypted, plaintext.as_slice());
        }

        /// AES-GCM different keys produce different ciphertexts
        #[test]
        fn aes_gcm_key_independence(
            key1 in prop::array::uniform32(any::<u8>()),
            key2 in prop::array::uniform32(any::<u8>()),
            nonce in prop::array::uniform12(any::<u8>()),
            plaintext in prop::collection::vec(any::<u8>(), 16..256)
        ) {
            use aws_lc_rs::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};

            prop_assume!(key1 != key2);

            // Encrypt with key1
            let uk1 = UnboundKey::new(&AES_256_GCM, &key1).unwrap();
            let lsk1 = LessSafeKey::new(uk1);
            let n1 = Nonce::assume_unique_for_key(nonce);
            let mut ct1 = plaintext.clone();
            lsk1.seal_in_place_append_tag(n1, Aad::empty(), &mut ct1).unwrap();

            // Encrypt with key2
            let uk2 = UnboundKey::new(&AES_256_GCM, &key2).unwrap();
            let lsk2 = LessSafeKey::new(uk2);
            let n2 = Nonce::assume_unique_for_key(nonce);
            let mut ct2 = plaintext.clone();
            lsk2.seal_in_place_append_tag(n2, Aad::empty(), &mut ct2).unwrap();

            // Ciphertexts should differ
            prop_assert_ne!(ct1, ct2);
        }

        /// AES-GCM modified ciphertext fails authentication
        #[test]
        fn aes_gcm_non_malleability(
            key in prop::array::uniform32(any::<u8>()),
            nonce in prop::array::uniform12(any::<u8>()),
            plaintext in prop::collection::vec(any::<u8>(), 16..256),
            flip_pos in 0usize..256usize
        ) {
            use aws_lc_rs::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};

            // Encrypt
            let uk = UnboundKey::new(&AES_256_GCM, &key).unwrap();
            let lsk = LessSafeKey::new(uk);
            let n = Nonce::assume_unique_for_key(nonce);
            let mut ciphertext = plaintext.clone();
            lsk.seal_in_place_append_tag(n, Aad::empty(), &mut ciphertext).unwrap();

            // Flip a bit in the ciphertext
            let pos = flip_pos % ciphertext.len();
            ciphertext[pos] ^= 0x01;

            // Decryption should fail
            let uk2 = UnboundKey::new(&AES_256_GCM, &key).unwrap();
            let lsk2 = LessSafeKey::new(uk2);
            let n2 = Nonce::assume_unique_for_key(nonce);
            let result = lsk2.open_in_place(n2, Aad::empty(), &mut ciphertext);

            prop_assert!(result.is_err());
        }
    }

    // ==========================================================================
    // ChaCha20-Poly1305 Property Tests
    // ==========================================================================

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(1000))]

        /// ChaCha20-Poly1305 roundtrip
        #[test]
        fn chacha20_poly1305_roundtrip(
            key in prop::array::uniform32(any::<u8>()),
            nonce in prop::array::uniform12(any::<u8>()),
            plaintext in prop::collection::vec(any::<u8>(), 0..4096)
        ) {
            use chacha20poly1305::{
                aead::{Aead, KeyInit},
                ChaCha20Poly1305,
            };

            let cipher = ChaCha20Poly1305::new(&key.into());

            let ciphertext = cipher.encrypt(&nonce.into(), plaintext.as_slice()).unwrap();
            let decrypted = cipher.decrypt(&nonce.into(), ciphertext.as_slice()).unwrap();

            prop_assert_eq!(decrypted, plaintext);
        }

        /// ChaCha20-Poly1305 ciphertext is larger than plaintext (by tag size)
        #[test]
        fn chacha20_poly1305_length_expansion(
            key in prop::array::uniform32(any::<u8>()),
            nonce in prop::array::uniform12(any::<u8>()),
            plaintext in prop::collection::vec(any::<u8>(), 0..4096)
        ) {
            use chacha20poly1305::{
                aead::{Aead, KeyInit},
                ChaCha20Poly1305,
            };

            let cipher = ChaCha20Poly1305::new(&key.into());
            let ciphertext = cipher.encrypt(&nonce.into(), plaintext.as_slice()).unwrap();

            // Ciphertext should be plaintext + 16-byte tag
            prop_assert_eq!(ciphertext.len(), plaintext.len() + 16);
        }
    }

    // ==========================================================================
    // Ed25519 Signature Property Tests
    // ==========================================================================

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(500))]

        /// Ed25519 sign/verify roundtrip
        #[test]
        fn ed25519_sign_verify_roundtrip(
            seed in prop::array::uniform32(any::<u8>()),
            message in prop::collection::vec(any::<u8>(), 0..4096)
        ) {
            use ed25519_dalek::{Signer, SigningKey, Verifier};

            let signing_key = SigningKey::from_bytes(&seed);
            let verifying_key = signing_key.verifying_key();

            let signature = signing_key.sign(&message);
            let result = verifying_key.verify(&message, &signature);

            prop_assert!(result.is_ok());
        }

        /// Ed25519 different keys produce different signatures
        #[test]
        fn ed25519_key_independence(
            seed1 in prop::array::uniform32(any::<u8>()),
            seed2 in prop::array::uniform32(any::<u8>()),
            message in prop::collection::vec(any::<u8>(), 16..256)
        ) {
            use ed25519_dalek::{Signer, SigningKey};

            prop_assume!(seed1 != seed2);

            let sk1 = SigningKey::from_bytes(&seed1);
            let sk2 = SigningKey::from_bytes(&seed2);

            let sig1 = sk1.sign(&message);
            let sig2 = sk2.sign(&message);

            prop_assert_ne!(sig1.to_bytes(), sig2.to_bytes());
        }

        /// Ed25519 signature verification fails for wrong message
        #[test]
        fn ed25519_wrong_message_fails(
            seed in prop::array::uniform32(any::<u8>()),
            message1 in prop::collection::vec(any::<u8>(), 16..256),
            message2 in prop::collection::vec(any::<u8>(), 16..256)
        ) {
            use ed25519_dalek::{Signer, SigningKey, Verifier};

            prop_assume!(message1 != message2);

            let signing_key = SigningKey::from_bytes(&seed);
            let verifying_key = signing_key.verifying_key();

            let signature = signing_key.sign(&message1);
            let result = verifying_key.verify(&message2, &signature);

            prop_assert!(result.is_err());
        }

        /// Ed25519 signature is deterministic
        #[test]
        fn ed25519_deterministic(
            seed in prop::array::uniform32(any::<u8>()),
            message in prop::collection::vec(any::<u8>(), 0..1024)
        ) {
            use ed25519_dalek::{Signer, SigningKey};

            let signing_key = SigningKey::from_bytes(&seed);

            let sig1 = signing_key.sign(&message);
            let sig2 = signing_key.sign(&message);

            prop_assert_eq!(sig1.to_bytes(), sig2.to_bytes());
        }
    }

    // ==========================================================================
    // X25519 Key Exchange Property Tests
    // ==========================================================================

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(500))]

        /// X25519 shared secret is symmetric
        #[test]
        fn x25519_symmetric_shared_secret(
            alice_secret in prop::array::uniform32(any::<u8>()),
            bob_secret in prop::array::uniform32(any::<u8>())
        ) {
            use x25519_dalek::{PublicKey, StaticSecret};

            let alice_sk = StaticSecret::from(alice_secret);
            let alice_pk = PublicKey::from(&alice_sk);

            let bob_sk = StaticSecret::from(bob_secret);
            let bob_pk = PublicKey::from(&bob_sk);

            let alice_shared = alice_sk.diffie_hellman(&bob_pk);
            let bob_shared = bob_sk.diffie_hellman(&alice_pk);

            prop_assert_eq!(alice_shared.as_bytes(), bob_shared.as_bytes());
        }

        /// X25519 different key pairs produce different shared secrets
        #[test]
        fn x25519_key_independence(
            alice_secret in prop::array::uniform32(any::<u8>()),
            bob_secret1 in prop::array::uniform32(any::<u8>()),
            bob_secret2 in prop::array::uniform32(any::<u8>())
        ) {
            use x25519_dalek::{PublicKey, StaticSecret};

            prop_assume!(bob_secret1 != bob_secret2);

            let alice_sk = StaticSecret::from(alice_secret);

            let bob_sk1 = StaticSecret::from(bob_secret1);
            let bob_pk1 = PublicKey::from(&bob_sk1);

            let bob_sk2 = StaticSecret::from(bob_secret2);
            let bob_pk2 = PublicKey::from(&bob_sk2);

            let shared1 = alice_sk.diffie_hellman(&bob_pk1);
            let shared2 = alice_sk.diffie_hellman(&bob_pk2);

            prop_assert_ne!(shared1.as_bytes(), shared2.as_bytes());
        }
    }

    // ==========================================================================
    // HKDF Property Tests
    // ==========================================================================

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(1000))]

        /// HKDF produces deterministic output
        #[test]
        fn hkdf_deterministic(
            ikm in prop::collection::vec(any::<u8>(), 16..64),
            salt in prop::collection::vec(any::<u8>(), 0..64),
            info in prop::collection::vec(any::<u8>(), 0..64),
            length in 16usize..128usize
        ) {
            use hkdf::Hkdf;
            use sha2::Sha256;

            let hk = Hkdf::<Sha256>::new(Some(&salt), &ikm);

            let mut okm1 = vec![0u8; length];
            let mut okm2 = vec![0u8; length];

            hk.expand(&info, &mut okm1).unwrap();
            hk.expand(&info, &mut okm2).unwrap();

            prop_assert_eq!(okm1, okm2);
        }

        /// HKDF different info produces different keys
        #[test]
        fn hkdf_info_independence(
            ikm in prop::collection::vec(any::<u8>(), 16..64),
            salt in prop::collection::vec(any::<u8>(), 16..64),
            info1 in prop::collection::vec(any::<u8>(), 1..64),
            info2 in prop::collection::vec(any::<u8>(), 1..64)
        ) {
            use hkdf::Hkdf;
            use sha2::Sha256;

            prop_assume!(info1 != info2);

            let hk = Hkdf::<Sha256>::new(Some(&salt), &ikm);

            let mut okm1 = vec![0u8; 32];
            let mut okm2 = vec![0u8; 32];

            hk.expand(&info1, &mut okm1).unwrap();
            hk.expand(&info2, &mut okm2).unwrap();

            prop_assert_ne!(okm1, okm2);
        }

        /// HKDF different IKM produces different keys
        #[test]
        fn hkdf_ikm_independence(
            ikm1 in prop::collection::vec(any::<u8>(), 16..64),
            ikm2 in prop::collection::vec(any::<u8>(), 16..64),
            salt in prop::collection::vec(any::<u8>(), 16..64),
            info in prop::collection::vec(any::<u8>(), 0..64)
        ) {
            use hkdf::Hkdf;
            use sha2::Sha256;

            prop_assume!(ikm1 != ikm2);

            let hk1 = Hkdf::<Sha256>::new(Some(&salt), &ikm1);
            let hk2 = Hkdf::<Sha256>::new(Some(&salt), &ikm2);

            let mut okm1 = vec![0u8; 32];
            let mut okm2 = vec![0u8; 32];

            hk1.expand(&info, &mut okm1).unwrap();
            hk2.expand(&info, &mut okm2).unwrap();

            prop_assert_ne!(okm1, okm2);
        }
    }

    // ==========================================================================
    // SHA-256 Property Tests
    // ==========================================================================

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(1000))]

        /// SHA-256 is deterministic
        #[test]
        fn sha256_deterministic(
            data in prop::collection::vec(any::<u8>(), 0..4096)
        ) {
            use sha2::{Digest, Sha256};

            let hash1 = Sha256::digest(&data);
            let hash2 = Sha256::digest(&data);

            prop_assert_eq!(hash1.as_slice(), hash2.as_slice());
        }

        /// SHA-256 produces fixed-length output
        #[test]
        fn sha256_output_length(
            data in prop::collection::vec(any::<u8>(), 0..4096)
        ) {
            use sha2::{Digest, Sha256};

            let hash = Sha256::digest(&data);

            prop_assert_eq!(hash.len(), 32);
        }

        /// SHA-256 different inputs produce different outputs (with high probability)
        #[test]
        fn sha256_collision_resistance(
            data1 in prop::collection::vec(any::<u8>(), 1..1024),
            data2 in prop::collection::vec(any::<u8>(), 1..1024)
        ) {
            use sha2::{Digest, Sha256};

            prop_assume!(data1 != data2);

            let hash1 = Sha256::digest(&data1);
            let hash2 = Sha256::digest(&data2);

            // Different inputs should produce different hashes
            // (collision probability is negligible for SHA-256)
            prop_assert_ne!(hash1.as_slice(), hash2.as_slice());
        }
    }

    // ==========================================================================
    // HMAC Property Tests
    // ==========================================================================

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(1000))]

        /// HMAC is deterministic
        #[test]
        fn hmac_deterministic(
            key in prop::collection::vec(any::<u8>(), 16..64),
            message in prop::collection::vec(any::<u8>(), 0..1024)
        ) {
            use hmac::{Hmac, Mac};
            use sha2::Sha256;

            type HmacSha256 = Hmac<Sha256>;

            let mut mac1 = HmacSha256::new_from_slice(&key).unwrap();
            mac1.update(&message);
            let result1 = mac1.finalize().into_bytes();

            let mut mac2 = HmacSha256::new_from_slice(&key).unwrap();
            mac2.update(&message);
            let result2 = mac2.finalize().into_bytes();

            prop_assert_eq!(result1.as_slice(), result2.as_slice());
        }

        /// HMAC different keys produce different tags
        #[test]
        fn hmac_key_independence(
            key1 in prop::collection::vec(any::<u8>(), 16..64),
            key2 in prop::collection::vec(any::<u8>(), 16..64),
            message in prop::collection::vec(any::<u8>(), 16..256)
        ) {
            use hmac::{Hmac, Mac};
            use sha2::Sha256;

            prop_assume!(key1 != key2);

            type HmacSha256 = Hmac<Sha256>;

            let mut mac1 = HmacSha256::new_from_slice(&key1).unwrap();
            mac1.update(&message);
            let tag1 = mac1.finalize().into_bytes();

            let mut mac2 = HmacSha256::new_from_slice(&key2).unwrap();
            mac2.update(&message);
            let tag2 = mac2.finalize().into_bytes();

            prop_assert_ne!(tag1.as_slice(), tag2.as_slice());
        }

        /// HMAC verification succeeds for correct tag
        #[test]
        fn hmac_verify_correct(
            key in prop::collection::vec(any::<u8>(), 16..64),
            message in prop::collection::vec(any::<u8>(), 0..1024)
        ) {
            use hmac::{Hmac, Mac};
            use sha2::Sha256;

            type HmacSha256 = Hmac<Sha256>;

            let mut mac = HmacSha256::new_from_slice(&key).unwrap();
            mac.update(&message);
            let tag = mac.finalize().into_bytes();

            let mut mac_verify = HmacSha256::new_from_slice(&key).unwrap();
            mac_verify.update(&message);
            let result = mac_verify.verify_slice(&tag);

            prop_assert!(result.is_ok());
        }
    }

    // ==========================================================================
    // Constant-Time Comparison Property Tests
    // ==========================================================================

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(1000))]

        /// Constant-time comparison is reflexive
        #[test]
        fn ct_eq_reflexive(
            data in prop::collection::vec(any::<u8>(), 1..256)
        ) {
            use subtle::ConstantTimeEq;

            let result: bool = data.ct_eq(&data).into();
            prop_assert!(result);
        }

        /// Constant-time comparison is symmetric
        #[test]
        fn ct_eq_symmetric(
            data1 in prop::collection::vec(any::<u8>(), 1..256),
            data2 in prop::collection::vec(any::<u8>(), 1..256)
        ) {
            use subtle::ConstantTimeEq;

            let result1: bool = data1.ct_eq(&data2).into();
            let result2: bool = data2.ct_eq(&data1).into();

            prop_assert_eq!(result1, result2);
        }

        /// Constant-time comparison detects differences
        #[test]
        fn ct_eq_difference_detection(
            data in prop::collection::vec(any::<u8>(), 1..256),
            pos in 0usize..256usize
        ) {
            use subtle::ConstantTimeEq;

            let mut modified = data.clone();
            let idx = pos % modified.len();
            modified[idx] ^= 0x01;

            let result: bool = data.ct_eq(&modified).into();
            prop_assert!(!result);
        }
    }
}
