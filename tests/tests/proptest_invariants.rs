//! Property-based tests for core cryptographic invariants.
//!
//! Covers the "any corruption → Err (or implicit rejection)" properties that
//! AEAD, KEM, and signature primitives must satisfy against attacker-chosen
//! bit-flips in the ciphertext / signature / tag. Counterexamples here are
//! protocol-breaking and would constitute CVE-class bugs — this file is a
//! regression gate against accidentally loosening those contracts.
//!
//! Complements the CAVP KAT suite (`tests/tests/fips_kat_*.rs`): KATs prove
//! "correct input → correct output"; these proptests prove "wrong input →
//! refusal".

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing
)]

use proptest::prelude::*;

// =============================================================================
// AES-256-GCM: tag corruption → Err, ciphertext corruption → Err
// =============================================================================

mod aes_gcm {
    use super::*;
    use latticearc::primitives::aead::{AeadCipher, aes_gcm::AesGcm256};

    // Any single-bit flip in the authentication tag must make decrypt fail.
    // This is the AES-GCM unforgeability contract (NIST SP 800-38D).
    proptest! {
        #[test]
        fn aes_256_gcm_any_tag_bit_flip_rejects_decrypt(
            plaintext in prop::collection::vec(any::<u8>(), 1..512),
            key in prop::array::uniform32(any::<u8>()),
            flip_byte in 0usize..16,
            flip_bit in 0u8..8,
        ) {
            let cipher = AesGcm256::new(&key).expect("cipher init");
            let nonce = AesGcm256::generate_nonce();
            let (ct, mut tag) = cipher.encrypt(&nonce, &plaintext, None).expect("encrypt");
            tag[flip_byte] ^= 1 << flip_bit;
            let result = cipher.decrypt(&nonce, &ct, &tag, None);
            prop_assert!(result.is_err(), "tag bit-flip at ({flip_byte},{flip_bit}) did not fail decrypt");
        }
    }

    // Any single-bit flip in the ciphertext must make decrypt fail.
    proptest! {
        #[test]
        fn aes_256_gcm_any_ciphertext_bit_flip_rejects_decrypt(
            plaintext in prop::collection::vec(any::<u8>(), 1..512),
            key in prop::array::uniform32(any::<u8>()),
            flip_index in 0usize..512,
            flip_bit in 0u8..8,
        ) {
            let cipher = AesGcm256::new(&key).expect("cipher init");
            let nonce = AesGcm256::generate_nonce();
            let (mut ct, tag) = cipher.encrypt(&nonce, &plaintext, None).expect("encrypt");
            prop_assume!(flip_index < ct.len());
            ct[flip_index] ^= 1 << flip_bit;
            let result = cipher.decrypt(&nonce, &ct, &tag, None);
            prop_assert!(result.is_err(), "ciphertext bit-flip at ({flip_index},{flip_bit}) did not fail decrypt");
        }
    }

    // AAD divergence between encrypt and decrypt must fail.
    proptest! {
        #[test]
        fn aes_256_gcm_aad_mismatch_rejects_decrypt(
            plaintext in prop::collection::vec(any::<u8>(), 1..256),
            key in prop::array::uniform32(any::<u8>()),
            aad_a in prop::collection::vec(any::<u8>(), 0..64),
            aad_b in prop::collection::vec(any::<u8>(), 0..64),
        ) {
            prop_assume!(aad_a != aad_b);
            let cipher = AesGcm256::new(&key).expect("cipher init");
            let nonce = AesGcm256::generate_nonce();
            let (ct, tag) = cipher.encrypt(&nonce, &plaintext, Some(&aad_a)).expect("encrypt");
            let result = cipher.decrypt(&nonce, &ct, &tag, Some(&aad_b));
            prop_assert!(result.is_err(), "AAD mismatch did not fail decrypt");
        }
    }
}

// =============================================================================
// ML-KEM: ciphertext corruption → implicit rejection
// =============================================================================
// FIPS 203 §7.3 mandates implicit rejection: decapsulation of an invalid
// ciphertext MUST NOT return an error; it returns a pseudo-random shared
// secret computed from the secret key and ciphertext. The invariant here is
// that the rejected secret is different from the legitimate secret, with
// cryptographic probability.

mod ml_kem {
    use super::*;
    use latticearc::primitives::kem::ml_kem::{MlKem, MlKemSecurityLevel};

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 32,  // keygen is expensive; 32 cases × 3 levels = 96 roundtrips
            .. ProptestConfig::default()
        })]

        #[test]
        fn ml_kem_768_ciphertext_bit_flip_changes_shared_secret(
            flip_index in 0usize..1088,  // ML-KEM-768 ciphertext is 1088 bytes
            flip_bit in 0u8..8,
        ) {
            let (pk, sk) = MlKem::generate_keypair(MlKemSecurityLevel::MlKem768).unwrap();
            let (legitimate_ss, ct) = MlKem::encapsulate(&pk).unwrap();
            let mut ct_bytes = ct.as_bytes().to_vec();
            prop_assume!(flip_index < ct_bytes.len());
            ct_bytes[flip_index] ^= 1 << flip_bit;
            let corrupted_ct = latticearc::primitives::kem::ml_kem::MlKemCiphertext::new(
                MlKemSecurityLevel::MlKem768,
                ct_bytes,
            )
            .unwrap();
            // Implicit rejection: decap of corrupted ct returns a pseudo-random
            // secret — not an error. We require it to differ from the legit one.
            let rejected_ss = MlKem::decapsulate(&sk, &corrupted_ct)
                .expect("implicit rejection must not error");
            prop_assert_ne!(
                rejected_ss.as_bytes(),
                legitimate_ss.as_bytes(),
                "implicit-rejection secret equalled legitimate secret after bit-flip"
            );
        }
    }
}

// =============================================================================
// ML-DSA: signature corruption → verify returns Ok(false)
// =============================================================================

mod ml_dsa {
    use super::*;
    use latticearc::primitives::sig::ml_dsa::{
        MlDsaParameterSet, MlDsaSignature, generate_keypair,
    };

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 16,  // ML-DSA-44 sign/verify is slower than AES
            .. ProptestConfig::default()
        })]

        #[test]
        fn ml_dsa_44_signature_bit_flip_rejects(
            message in prop::collection::vec(any::<u8>(), 1..256),
            flip_index in 0usize..2420,  // ML-DSA-44 signature is 2420 bytes
            flip_bit in 0u8..8,
        ) {
            let (pk, sk) = generate_keypair(MlDsaParameterSet::MlDsa44).unwrap();
            let sig = sk.sign(&message, b"").unwrap();
            let mut sig_bytes = sig.as_bytes().to_vec();
            prop_assume!(flip_index < sig_bytes.len());
            sig_bytes[flip_index] ^= 1 << flip_bit;
            let corrupted_sig =
                MlDsaSignature::new(MlDsaParameterSet::MlDsa44, sig_bytes).unwrap();
            // Bit-flipped signature must not verify; function either returns
            // Ok(false) or Err — both acceptable per FIPS 204 unforgeability.
            if let Ok(v) = pk.verify(&message, &corrupted_sig, b"") {
                prop_assert!(!v, "bit-flipped signature verified as valid");
            }
        }

        #[test]
        fn ml_dsa_44_message_bit_flip_rejects(
            message in prop::collection::vec(any::<u8>(), 16..256),
            flip_index in 0usize..256,
            flip_bit in 0u8..8,
        ) {
            let (pk, sk) = generate_keypair(MlDsaParameterSet::MlDsa44).unwrap();
            let sig = sk.sign(&message, b"").unwrap();
            let mut corrupted_msg = message;
            prop_assume!(flip_index < corrupted_msg.len());
            corrupted_msg[flip_index] ^= 1 << flip_bit;
            let valid = pk.verify(&corrupted_msg, &sig, b"")
                .expect("verify of well-formed sig against corrupted message must succeed");
            prop_assert!(!valid, "signature verified against a tampered message");
        }
    }
}

// =============================================================================
// HMAC-SHA256: tag corruption → verify returns false
// =============================================================================

mod hmac_sha256 {
    use super::*;
    use latticearc::primitives::mac::hmac::{hmac_sha256, verify_hmac_sha256};

    proptest! {
        #[test]
        fn hmac_sha256_tag_bit_flip_rejects(
            data in prop::collection::vec(any::<u8>(), 0..512),
            key in prop::collection::vec(any::<u8>(), 16..64),
            flip_byte in 0usize..32,
            flip_bit in 0u8..8,
        ) {
            let mut tag = hmac_sha256(&key, &data).unwrap();
            tag[flip_byte] ^= 1 << flip_bit;
            prop_assert!(
                !verify_hmac_sha256(&key, &data, &tag),
                "bit-flipped HMAC tag verified as valid"
            );
        }

        #[test]
        fn hmac_sha256_wrong_key_rejects(
            data in prop::collection::vec(any::<u8>(), 0..512),
            key_a in prop::collection::vec(any::<u8>(), 16..64),
            key_b in prop::collection::vec(any::<u8>(), 16..64),
        ) {
            prop_assume!(key_a != key_b);
            let tag = hmac_sha256(&key_a, &data).unwrap();
            prop_assert!(
                !verify_hmac_sha256(&key_b, &data, &tag),
                "HMAC verified with wrong key"
            );
        }
    }
}

// =============================================================================
// Roundtrip invariants — the positive control for the rejection tests above.
// These are simple enough to live here rather than in a separate file.
// =============================================================================

mod roundtrip {
    use super::*;
    use latticearc::primitives::aead::{AeadCipher, aes_gcm::AesGcm256};

    proptest! {
        #[test]
        fn aes_256_gcm_encrypt_decrypt_roundtrip(
            plaintext in prop::collection::vec(any::<u8>(), 0..1024),
            key in prop::array::uniform32(any::<u8>()),
        ) {
            let cipher = AesGcm256::new(&key).unwrap();
            let nonce = AesGcm256::generate_nonce();
            let (ct, tag) = cipher.encrypt(&nonce, &plaintext, None).unwrap();
            let recovered = cipher.decrypt(&nonce, &ct, &tag, None).unwrap();
            prop_assert_eq!(recovered.as_slice(), plaintext.as_slice());
        }
    }
}
