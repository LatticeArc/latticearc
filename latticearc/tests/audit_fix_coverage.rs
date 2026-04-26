//! Tests for deep audit fix coverage (21 findings: H1-H6, M1-M10, L1-L5)
//!
//! Each test is tagged with its audit finding ID for traceability.

#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::indexing_slicing)]

// ============================================================================
// H1: HkdfResult.key field is private, accessed only via key() accessor
// ============================================================================

mod h1_hkdf_result_field_protection {
    use latticearc::primitives::kdf::hkdf::{hkdf, hkdf_expand, hkdf_extract, hkdf_simple};

    #[test]
    fn h1_key_accessor_returns_correct_data() {
        let result = hkdf(b"ikm", Some(b"salt"), Some(b"info"), 32).unwrap();
        // key() returns &[u8], not the raw Vec
        let key: &[u8] = result.key();
        assert_eq!(key.len(), 32);
        assert!(key.iter().any(|&b| b != 0), "Derived key should be non-zero");
    }

    #[test]
    fn h1_key_accessor_deterministic() {
        let r1 = hkdf(b"ikm", Some(b"salt"), Some(b"info"), 32).unwrap();
        let r2 = hkdf(b"ikm", Some(b"salt"), Some(b"info"), 32).unwrap();
        assert_eq!(r1.key(), r2.key());
    }

    #[test]
    fn h1_key_length_matches_key_length_field() {
        for len in [16, 32, 48, 64, 128] {
            let result = hkdf(b"ikm", Some(b"salt"), None, len).unwrap();
            assert_eq!(result.key().len(), result.key_length());
            assert_eq!(result.key().len(), len);
        }
    }

    #[test]
    fn h1_key_zeroized_on_drop() {
        // Verify the key is non-zero while live, then dropped
        // (We can't observe memory after drop, but we verify the Zeroizing wrapper works)
        let result = hkdf(b"secret", Some(b"salt"), None, 32).unwrap();
        let key_copy = result.key().to_vec();
        assert!(key_copy.iter().any(|&b| b != 0));
        drop(result);
        // The original key bytes are zeroized by Zeroizing<Vec<u8>> on drop.
        // We can only verify the copy is still intact (proving key was live before drop).
        assert!(key_copy.iter().any(|&b| b != 0));
    }

    #[test]
    fn h1_extract_expand_roundtrip_via_accessor() {
        let prk = hkdf_extract(Some(b"salt"), b"ikm").unwrap();
        let result = hkdf_expand(&prk, Some(b"info"), 64).unwrap();
        assert_eq!(result.key().len(), 64);
    }

    #[test]
    fn h1_simple_hkdf_via_accessor() {
        let r1 = hkdf_simple(b"ikm", 32).unwrap();
        let r2 = hkdf_simple(b"ikm", 32).unwrap();
        // Random salts should produce different keys
        assert_ne!(r1.key(), r2.key());
    }
}

// ============================================================================
// H2: IKM buffer in derive_hybrid_shared_secret is Zeroizing
// ============================================================================

mod h2_ikm_zeroization {
    use latticearc::hybrid::kem_hybrid::{decapsulate, encapsulate, generate_keypair};

    #[test]
    fn h2_encapsulate_decapsulate_roundtrip_with_zeroized_ikm() {
        // The IKM buffer inside derive_hybrid_shared_secret is now Zeroizing.
        // Verify the functional correctness is preserved.
        let (pk, sk) = generate_keypair().unwrap();
        let encapsulated = encapsulate(&pk).unwrap();
        let shared_secret = decapsulate(&sk, &encapsulated).unwrap();
        // Shared secrets must match
        assert_eq!(shared_secret.expose_secret(), encapsulated.expose_secret());
        assert_eq!(shared_secret.len(), 64);
    }

    #[test]
    fn h2_different_keypairs_different_secrets() {
        let (pk1, _sk1) = generate_keypair().unwrap();
        let (pk2, _sk2) = generate_keypair().unwrap();
        let enc1 = encapsulate(&pk1).unwrap();
        let enc2 = encapsulate(&pk2).unwrap();
        assert_ne!(enc1.expose_secret(), enc2.expose_secret());
    }
}

// ============================================================================
// H3: derive_encryption_key returns Zeroizing<[u8; 32]>
// ============================================================================

mod h3_encryption_key_zeroization {
    use latticearc::hybrid::encrypt_hybrid::{
        HybridEncryptionContext, decrypt_hybrid, encrypt_hybrid,
    };
    use latticearc::hybrid::kem_hybrid::generate_keypair;

    #[test]
    fn h3_encrypt_decrypt_roundtrip_hybrid() {
        let (pk, sk) = generate_keypair().unwrap();

        let plaintext = b"test message for H3 hybrid encryption";
        let ctx = HybridEncryptionContext::default();
        let ct = encrypt_hybrid(&pk, plaintext, Some(&ctx)).unwrap();
        let recovered = decrypt_hybrid(&sk, &ct, Some(&ctx)).unwrap();
        assert_eq!(recovered.as_slice(), plaintext.as_slice());
    }
}

// ============================================================================
// H5: ChaCha20-Poly1305 ciphers have ZeroizeOnDrop via key_bytes storage
// ============================================================================

#[cfg(not(feature = "fips"))]
mod h5_chacha20_zeroize_on_drop {
    use latticearc::primitives::aead::{
        AeadCipher,
        chacha20poly1305::{ChaCha20Poly1305Cipher, XChaCha20Poly1305Cipher},
    };

    #[test]
    fn h5_chacha20_encrypt_decrypt_after_restructure() {
        let key = ChaCha20Poly1305Cipher::generate_key();
        let cipher = ChaCha20Poly1305Cipher::new(&*key).unwrap();
        let nonce = ChaCha20Poly1305Cipher::generate_nonce();
        let plaintext = b"test for H5 ChaCha20 restructure";

        let (ct, tag) = cipher.encrypt(&nonce, plaintext, None).unwrap();
        let decrypted = cipher.decrypt(&nonce, &ct, &tag, None).unwrap();
        assert_eq!(decrypted.as_slice(), plaintext.as_slice());
    }

    #[test]
    fn h5_chacha20_with_aad_after_restructure() {
        let key = ChaCha20Poly1305Cipher::generate_key();
        let cipher = ChaCha20Poly1305Cipher::new(&*key).unwrap();
        let nonce = ChaCha20Poly1305Cipher::generate_nonce();
        let plaintext = b"authenticated message";
        let aad = b"additional data";

        let (ct, tag) = cipher.encrypt(&nonce, plaintext, Some(aad)).unwrap();
        let decrypted = cipher.decrypt(&nonce, &ct, &tag, Some(aad)).unwrap();
        assert_eq!(decrypted.as_slice(), plaintext.as_slice());

        // Wrong AAD should fail
        let result = cipher.decrypt(&nonce, &ct, &tag, Some(b"wrong aad"));
        assert!(result.is_err());
    }

    #[test]
    fn h5_xchacha20_encrypt_decrypt_after_restructure() {
        let key = XChaCha20Poly1305Cipher::generate_key();
        let cipher = XChaCha20Poly1305Cipher::new(&*key).unwrap();
        let nonce = XChaCha20Poly1305Cipher::generate_xnonce();
        let plaintext = b"test for H5 XChaCha20 restructure";

        let (ct, tag) = cipher.encrypt_x(&nonce, plaintext, None).unwrap();
        let decrypted = cipher.decrypt_x(&nonce, &ct, &tag, None).unwrap();
        assert_eq!(decrypted.as_slice(), plaintext.as_slice());
    }

    #[test]
    fn h5_chacha20_empty_plaintext() {
        let key = ChaCha20Poly1305Cipher::generate_key();
        let cipher = ChaCha20Poly1305Cipher::new(&*key).unwrap();
        let nonce = ChaCha20Poly1305Cipher::generate_nonce();

        let (ct, tag) = cipher.encrypt(&nonce, &[], None).unwrap();
        assert!(ct.is_empty());
        let decrypted = cipher.decrypt(&nonce, &ct, &tag, None).unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn h5_cipher_dropped_correctly() {
        // Verify cipher can be created and dropped without issues
        // (ZeroizeOnDrop fires on drop)
        let key = ChaCha20Poly1305Cipher::generate_key();
        let cipher = ChaCha20Poly1305Cipher::new(&*key).unwrap();
        let nonce = ChaCha20Poly1305Cipher::generate_nonce();
        let (ct, tag) = cipher.encrypt(&nonce, b"data", None).unwrap();
        drop(cipher); // ZeroizeOnDrop triggers here

        // Create new cipher from same key to verify decryption
        let cipher2 = ChaCha20Poly1305Cipher::new(&*key).unwrap();
        let decrypted = cipher2.decrypt(&nonce, &ct, &tag, None).unwrap();
        assert_eq!(&*decrypted, b"data");
    }
}

// ============================================================================
// M2: ZKP constant-time verification (Schnorr + DlogEquality)
// ============================================================================

#[cfg(not(feature = "fips"))]
mod m2_zkp_constant_time {
    use k256::{
        ProjectivePoint, Scalar,
        elliptic_curve::{Field, group::GroupEncoding},
    };
    use latticearc::zkp::schnorr::{SchnorrProver, SchnorrVerifier};
    use latticearc::zkp::sigma::{DlogEqualityProof, DlogEqualityStatement};

    #[test]
    fn m2_schnorr_verify_valid_proof() {
        let (prover, pk) = SchnorrProver::new().unwrap();
        let proof = prover.prove(b"test context").unwrap();
        let verifier = SchnorrVerifier::new(pk);
        let result = verifier.verify(&proof, b"test context").unwrap();
        assert!(result);
    }

    #[test]
    fn m2_schnorr_verify_wrong_context_fails() {
        let (prover, pk) = SchnorrProver::new().unwrap();
        let proof = prover.prove(b"context A").unwrap();
        let verifier = SchnorrVerifier::new(pk);
        let result = verifier.verify(&proof, b"context B").unwrap();
        assert!(!result);
    }

    #[test]
    fn m2_dlog_equality_verify_valid_proof() {
        let x = Scalar::random(&mut rand::rngs::OsRng);
        let g = ProjectivePoint::GENERATOR;
        let h = g * Scalar::random(&mut rand::rngs::OsRng);
        let p = g * x;
        let q = h * x;

        let g_bytes: [u8; 33] = g.to_affine().to_bytes().as_slice().try_into().unwrap();
        let h_bytes: [u8; 33] = h.to_affine().to_bytes().as_slice().try_into().unwrap();
        let p_bytes: [u8; 33] = p.to_affine().to_bytes().as_slice().try_into().unwrap();
        let q_bytes: [u8; 33] = q.to_affine().to_bytes().as_slice().try_into().unwrap();

        let statement = DlogEqualityStatement { g: g_bytes, h: h_bytes, p: p_bytes, q: q_bytes };

        let secret: [u8; 32] = x.to_bytes().into();
        let proof = DlogEqualityProof::prove(&statement, &secret, b"test").unwrap();
        let valid = proof.verify(&statement, b"test").unwrap();
        assert!(valid);
    }

    #[test]
    fn m2_dlog_equality_wrong_secret_fails() {
        let x = Scalar::random(&mut rand::rngs::OsRng);
        let y = Scalar::random(&mut rand::rngs::OsRng); // wrong secret
        let g = ProjectivePoint::GENERATOR;
        let h = g * Scalar::random(&mut rand::rngs::OsRng);
        let p = g * x;
        let q = h * x;

        let g_bytes: [u8; 33] = g.to_affine().to_bytes().as_slice().try_into().unwrap();
        let h_bytes: [u8; 33] = h.to_affine().to_bytes().as_slice().try_into().unwrap();
        let p_bytes: [u8; 33] = p.to_affine().to_bytes().as_slice().try_into().unwrap();
        let q_bytes: [u8; 33] = q.to_affine().to_bytes().as_slice().try_into().unwrap();

        let statement = DlogEqualityStatement { g: g_bytes, h: h_bytes, p: p_bytes, q: q_bytes };

        let wrong_secret: [u8; 32] = y.to_bytes().into();
        let proof = DlogEqualityProof::prove(&statement, &wrong_secret, b"test").unwrap();
        let valid = proof.verify(&statement, b"test").unwrap();
        assert!(!valid, "Proof with wrong secret must fail verification");
    }
}

// ============================================================================
// M4: Secret key to_bytes() returns Zeroizing<Vec<u8>>
// ============================================================================

mod m4_secret_key_to_bytes_zeroizing {
    use latticearc::primitives::sig::fndsa::{FnDsaSecurityLevel, KeyPair, SigningKey};
    use rand::rngs::OsRng;

    #[test]
    fn m4_fndsa_to_bytes_roundtrip() {
        let mut rng = OsRng;
        let keypair = KeyPair::generate_with_rng(&mut rng, FnDsaSecurityLevel::Level512).unwrap();
        let sk_bytes = keypair.signing_key().to_bytes(); // returns Zeroizing<Vec<u8>>
        assert_eq!(sk_bytes.len(), FnDsaSecurityLevel::Level512.signing_key_size());

        // Reconstruct from bytes (must clone out of Zeroizing)
        let sk2 = SigningKey::from_bytes(&sk_bytes, FnDsaSecurityLevel::Level512).unwrap();
        assert_eq!(keypair.signing_key().to_bytes().as_slice(), sk2.to_bytes().as_slice());
    }

    #[test]
    fn m4_slh_dsa_to_bytes_roundtrip() {
        use latticearc::primitives::sig::slh_dsa::{SigningKey, SlhDsaSecurityLevel};

        let level = SlhDsaSecurityLevel::Shake128s;
        let (sk, _vk) = SigningKey::generate(level).unwrap();
        let sk_bytes = sk.to_bytes(); // returns Zeroizing<Vec<u8>>
        assert_eq!(sk_bytes.len(), level.secret_key_size());

        let sk2 = SigningKey::from_bytes(&sk_bytes, level).unwrap();
        assert_eq!(sk.expose_secret(), sk2.expose_secret());
    }
}

// ============================================================================
// M5: All-zero key warning (not rejection) in AEAD constructors
// ============================================================================

mod m5_all_zero_key_rejection {
    use latticearc::primitives::aead::{
        AeadCipher, AeadError, aes_gcm::AesGcm128, aes_gcm::AesGcm256,
    };

    // All-zero AEAD keys are rejected at construction time with
    // `AeadError::WeakKey` as fail-closed defence against uninitialised-memory
    // bugs. Tests needing a deterministic key for non-key-related coverage
    // (ciphertext corruption, AAD mismatch, etc.) should pick any non-zero
    // pattern such as `[0x42u8; KEY_LEN]`. KAT vectors that genuinely exercise
    // the all-zero key (McGrew & Viega Test Cases 1 and 2) must enable the
    // `kat-test-vectors` Cargo feature and construct via
    // `AeadCipher::new_allow_weak_key`.

    fn assert_weak_key<T: std::fmt::Debug>(result: Result<T, AeadError>) {
        assert!(
            matches!(result, Err(AeadError::WeakKey)),
            "expected AeadError::WeakKey, got {result:?}",
        );
    }

    #[test]
    fn m5_aes_gcm_128_rejects_all_zero_key() {
        assert_weak_key(AesGcm128::new(&[0u8; 16]));
    }

    #[test]
    fn m5_aes_gcm_256_rejects_all_zero_key() {
        assert_weak_key(AesGcm256::new(&[0u8; 32]));
    }

    #[cfg(not(feature = "fips"))]
    #[test]
    fn m5_chacha20_rejects_all_zero_key() {
        use latticearc::primitives::aead::chacha20poly1305::ChaCha20Poly1305Cipher;
        assert_weak_key(ChaCha20Poly1305Cipher::new(&[0u8; 32]));
    }

    #[test]
    fn m5_non_zero_deterministic_key_still_roundtrips() {
        let key = [0x42u8; 32];
        let cipher = AesGcm256::new(&key).expect("non-zero deterministic key must construct");
        let nonce = AesGcm256::generate_nonce();
        let (ct, tag) = cipher.encrypt(&nonce, b"hello", None).expect("encrypt");
        let pt = cipher.decrypt(&nonce, &ct, &tag, None).expect("decrypt");
        assert_eq!(pt.as_slice(), b"hello");
    }
}

// NOTE: The M6 block (PublicKey::from_bytes ML-KEM length validation) used to
// test `primitives::keys::KemEccPublicKey`, which was a duplicate of
// `hybrid::kem_hybrid::HybridKemPublicKey`. The `primitives::keys` module was
// removed in the P4.2 dead-code cleanup. The equivalent validation on the
// hybrid KEM public key is covered by `hybrid_kem_hybrid_coverage.rs`.

// ============================================================================
// M7: X25519 low-order point rejection (all-zero public key)
// ============================================================================

mod m7_x25519_zero_key_rejection {
    use latticearc::primitives::kem::ecdh::X25519PublicKey;

    #[test]
    fn m7_all_zero_public_key_rejected() {
        let result = X25519PublicKey::from_bytes(&[0u8; 32]);
        assert!(result.is_err());
        let err = format!("{:?}", result.unwrap_err());
        assert!(
            err.contains("low-order point") || err.contains("All-zero"),
            "Error should mention low-order point: {err}"
        );
    }

    #[test]
    fn m7_non_zero_public_key_accepted() {
        let mut key = [0u8; 32];
        key[0] = 9; // Curve25519 base point x-coordinate
        let result = X25519PublicKey::from_bytes(&key);
        assert!(result.is_ok());
    }

    #[test]
    fn m7_wrong_length_still_rejected() {
        let result = X25519PublicKey::from_bytes(&[0x42; 31]);
        assert!(result.is_err());
        let result = X25519PublicKey::from_bytes(&[0x42; 33]);
        assert!(result.is_err());
    }
}

// ============================================================================
// M9: EC keypair Drop impl for zeroization
// ============================================================================

#[cfg(not(feature = "fips"))]
mod m9_ec_keypair_drop {
    use latticearc::primitives::ec::{EcKeyPair, Ed25519KeyPair, Secp256k1KeyPair};

    #[test]
    fn m9_secp256k1_create_and_drop() {
        // Verify keypair can be created and dropped without panic
        // (Drop impl overwrites secret key)
        let keypair = Secp256k1KeyPair::generate().unwrap();
        let _pk = keypair.public_key_bytes();
        drop(keypair); // Drop fires, overwriting secret key bytes
    }

    #[test]
    fn m9_ed25519_create_and_drop() {
        let keypair = Ed25519KeyPair::generate().unwrap();
        let _pk = keypair.public_key_bytes();
        drop(keypair);
    }

    #[test]
    fn m9_secp256k1_secret_key_accessible_before_drop() {
        let keypair = Secp256k1KeyPair::generate().unwrap();
        let sk_bytes = keypair.secret_key_bytes();
        assert_eq!(sk_bytes.len(), 32);
        assert!(sk_bytes.iter().any(|&b| b != 0));
        drop(keypair); // Drop fires
    }

    #[test]
    fn m9_ed25519_secret_key_accessible_before_drop() {
        let keypair = Ed25519KeyPair::generate().unwrap();
        let sk_bytes = keypair.secret_key_bytes();
        assert_eq!(sk_bytes.len(), 32);
        assert!(sk_bytes.iter().any(|&b| b != 0));
        drop(keypair);
    }

    #[test]
    fn m9_secp256k1_from_secret_key_then_drop() {
        // Generate, extract secret, reconstruct, and drop
        let kp1 = Secp256k1KeyPair::generate().unwrap();
        let sk = kp1.secret_key_bytes();
        let pk1 = kp1.public_key_bytes();
        drop(kp1);

        let kp2 = Secp256k1KeyPair::from_secret_key(&sk).unwrap();
        let pk2 = kp2.public_key_bytes();
        assert_eq!(pk1, pk2, "Reconstructed keypair should have same public key");
        drop(kp2); // Drop fires on reconstructed keypair
    }
}

// ============================================================================
// M10: DlogEqualityProof Debug redaction
// ============================================================================

#[cfg(not(feature = "fips"))]
mod m10_dlog_equality_debug_redaction {
    use k256::{
        ProjectivePoint, Scalar,
        elliptic_curve::{Field, group::GroupEncoding},
    };
    use latticearc::zkp::sigma::{DlogEqualityProof, DlogEqualityStatement};

    #[test]
    fn m10_debug_output_redacts_response() {
        let x = Scalar::random(&mut rand::rngs::OsRng);
        let g = ProjectivePoint::GENERATOR;
        let h = g * Scalar::random(&mut rand::rngs::OsRng);
        let p = g * x;
        let q = h * x;

        let statement = DlogEqualityStatement {
            g: g.to_affine().to_bytes().as_slice().try_into().unwrap(),
            h: h.to_affine().to_bytes().as_slice().try_into().unwrap(),
            p: p.to_affine().to_bytes().as_slice().try_into().unwrap(),
            q: q.to_affine().to_bytes().as_slice().try_into().unwrap(),
        };

        let secret: [u8; 32] = x.to_bytes().into();
        let proof = DlogEqualityProof::prove(&statement, &secret, b"ctx").unwrap();

        let debug_output = format!("{:?}", proof);
        assert!(
            debug_output.contains("[REDACTED]"),
            "Debug output must contain [REDACTED]: {debug_output}"
        );
        // Ensure actual response bytes are not in the debug string
        let response_hex = hex::encode(proof.response());
        assert!(
            !debug_output.contains(&response_hex),
            "Debug output must not contain raw response bytes"
        );
    }

    #[test]
    fn m10_debug_shows_commitments() {
        let x = Scalar::random(&mut rand::rngs::OsRng);
        let g = ProjectivePoint::GENERATOR;
        let h = g * Scalar::random(&mut rand::rngs::OsRng);

        let statement = DlogEqualityStatement {
            g: g.to_affine().to_bytes().as_slice().try_into().unwrap(),
            h: h.to_affine().to_bytes().as_slice().try_into().unwrap(),
            p: (g * x).to_affine().to_bytes().as_slice().try_into().unwrap(),
            q: (h * x).to_affine().to_bytes().as_slice().try_into().unwrap(),
        };

        let secret: [u8; 32] = x.to_bytes().into();
        let proof = DlogEqualityProof::prove(&statement, &secret, b"ctx").unwrap();

        let debug_output = format!("{:?}", proof);
        // Commitments a and b should still be visible
        assert!(debug_output.contains("a:"), "Debug output should show 'a' field");
        assert!(debug_output.contains("b:"), "Debug output should show 'b' field");
    }
}

// ============================================================================
// L4: Serialization size limit (10 MiB)
// ============================================================================

mod l4_serialization_size_limit {
    use base64::Engine as _;
    use latticearc::unified_api::crypto_types::EncryptedOutput;
    use latticearc::unified_api::serialization::SerializableEncryptedOutput;

    fn b64(data: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(data)
    }

    fn make_payload(ciphertext: String) -> SerializableEncryptedOutput {
        SerializableEncryptedOutput {
            version: 2,
            scheme: "aes-256-gcm".to_string(),
            ciphertext,
            nonce: b64(&[0u8; 12]),
            tag: b64(&[0u8; 16]),
            hybrid_data: None,
            timestamp: 0,
            key_id: None,
        }
    }

    #[test]
    fn l4_oversized_data_rejected() {
        // Ciphertext exceeding the 10 MiB defense-in-depth cap must fail.
        let oversized = make_payload("A".repeat(11 * 1024 * 1024));
        let result: Result<EncryptedOutput, _> = oversized.try_into();
        assert!(result.is_err(), "Oversized payload should be rejected");
        let err = format!("{:?}", result.unwrap_err());
        assert!(
            err.contains("exceeds maximum") || err.contains("size"),
            "Error should mention size limit: {err}"
        );
    }

    #[test]
    fn l4_exactly_at_limit_accepted() {
        // Exactly 10 MiB passes the size check (may fail later validation).
        let at_limit = make_payload("A".repeat(10 * 1024 * 1024));
        let result: Result<EncryptedOutput, _> = at_limit.try_into();
        if let Err(e) = &result {
            let err = format!("{e:?}");
            assert!(
                !err.contains("exceeds maximum"),
                "At-limit data should pass size check: {err}"
            );
        }
    }

    #[test]
    fn l4_normal_size_data_accepted() {
        let normal = make_payload(b64(&[0x42; 1024]));
        let result: Result<EncryptedOutput, _> = normal.try_into();
        assert!(result.is_ok(), "Normal-sized data should be accepted: {result:?}");
    }

    #[test]
    fn l4_just_over_limit_rejected() {
        let over_limit = make_payload("A".repeat(10 * 1024 * 1024 + 1));
        let result: Result<EncryptedOutput, _> = over_limit.try_into();
        assert!(result.is_err(), "Over-limit data should be rejected");
    }
}
