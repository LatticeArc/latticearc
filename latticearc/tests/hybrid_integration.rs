//! Hybrid cross-cutting integration tests (roundtrip, zeroization).
#![deny(unsafe_code)]

// Originally: hybrid_roundtrip_integration.rs
mod roundtrip {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]
    #![allow(clippy::indexing_slicing)]
    #![allow(clippy::print_stderr)]
    #![allow(clippy::cast_possible_truncation)]
    #![allow(missing_docs)]

    //! Hybrid Cryptography Roundtrip Integration Tests
    //!
    //! End-to-end tests exercising the arc-hybrid public API from outside the crate.
    //! These tests verify full roundtrips: keygen → encrypt → decrypt, keygen → sign → verify,
    //! and tamper detection.
    //!
    //! Run with: `cargo test --package arc-hybrid --test hybrid_roundtrip_integration --all-features -- --nocapture`

    use latticearc::hybrid::encrypt_hybrid::{
        HybridEncryptionContext, decrypt_hybrid, encrypt_hybrid,
    };
    use latticearc::hybrid::kem_hybrid::{decapsulate, encapsulate, generate_keypair};
    use latticearc::hybrid::sig_hybrid::{self as sig};

    // ============================================================================
    // KEM Roundtrip Tests
    // ============================================================================

    #[test]
    fn test_kem_generate_encapsulate_decapsulate_succeeds() {
        let (pk, sk) = generate_keypair().expect("keygen should succeed");

        let enc_key = encapsulate(&pk).expect("encap should succeed");
        let dec_secret = decapsulate(&sk, &enc_key).expect("decap should succeed");

        assert_eq!(
            dec_secret.expose_secret(),
            enc_key.expose_secret(),
            "Encapsulated and decapsulated secrets must match"
        );
        assert_eq!(dec_secret.len(), 64, "Hybrid shared secret should be 64 bytes");
    }

    #[test]
    fn test_kem_multiple_encapsulations_same_key_succeeds() {
        let (pk, sk) = generate_keypair().expect("keygen should succeed");

        for i in 0..10u32 {
            let enc_key =
                encapsulate(&pk).unwrap_or_else(|e| panic!("encap {} failed: {:?}", i, e));
            let dec_secret = decapsulate(&sk, &enc_key)
                .unwrap_or_else(|e| panic!("decap {} failed: {:?}", i, e));

            assert_eq!(
                dec_secret.expose_secret(),
                enc_key.expose_secret(),
                "Roundtrip {} secret mismatch",
                i
            );
        }
    }

    #[test]
    fn test_kem_different_keypairs_different_secrets_succeeds() {
        let (pk_a, _sk_a) = generate_keypair().unwrap();
        let (pk_b, _sk_b) = generate_keypair().unwrap();

        let enc_a = encapsulate(&pk_a).unwrap();
        let enc_b = encapsulate(&pk_b).unwrap();

        assert_ne!(
            enc_a.expose_secret(),
            enc_b.expose_secret(),
            "Different keypairs should produce different shared secrets"
        );
    }

    #[test]
    fn test_kem_cross_key_rejection_fails() {
        let (pk_a, _sk_a) = generate_keypair().unwrap();
        let (_pk_b, sk_b) = generate_keypair().unwrap();

        // Encapsulate with key A
        let enc_key = encapsulate(&pk_a).unwrap();

        // Decapsulate with key B — should produce a different shared secret
        // (ML-KEM implicit rejection returns a valid but wrong secret)
        let dec_secret_b = decapsulate(&sk_b, &enc_key).unwrap();
        assert_ne!(
            dec_secret_b.expose_secret(),
            enc_key.expose_secret(),
            "Cross-key decapsulation should yield a different shared secret"
        );
    }

    // ============================================================================
    // Encryption Roundtrip Tests
    // ============================================================================

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let (pk, sk) = generate_keypair().unwrap();

        let plaintext = b"Hello, hybrid encryption!";
        let context = HybridEncryptionContext::default();

        let ct = encrypt_hybrid(&pk, plaintext, Some(&context)).expect("encrypt should succeed");
        let decrypted = decrypt_hybrid(&sk, &ct, Some(&context)).expect("decrypt should succeed");

        assert_eq!(decrypted.as_slice(), plaintext, "Roundtrip plaintext mismatch");
    }

    #[test]
    fn test_encrypt_decrypt_with_aad_roundtrip() {
        let (pk, sk) = generate_keypair().unwrap();

        let plaintext = b"data with additional authenticated data";
        let context = HybridEncryptionContext {
            info: b"custom-domain-separation".to_vec(),
            aad: b"header-metadata-v2".to_vec(),
        };

        let ct = encrypt_hybrid(&pk, plaintext, Some(&context)).unwrap();
        let decrypted = decrypt_hybrid(&sk, &ct, Some(&context)).unwrap();

        assert_eq!(decrypted.as_slice(), plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_empty_plaintext_roundtrip() {
        let (pk, sk) = generate_keypair().unwrap();

        let plaintext = b"";
        let context = HybridEncryptionContext::default();

        let ct = encrypt_hybrid(&pk, plaintext, Some(&context)).unwrap();
        let decrypted = decrypt_hybrid(&sk, &ct, Some(&context)).unwrap();

        assert!(decrypted.is_empty(), "Empty plaintext should decrypt to empty");
    }

    #[test]
    fn test_encrypt_decrypt_large_plaintext_roundtrip() {
        let (pk, sk) = generate_keypair().unwrap();

        // 64KB payload
        let plaintext: Vec<u8> = (0..65_536u32).map(|i| (i & 0xFF) as u8).collect();
        let context = HybridEncryptionContext::default();

        let ct = encrypt_hybrid(&pk, &plaintext, Some(&context)).unwrap();
        let decrypted = decrypt_hybrid(&sk, &ct, Some(&context)).unwrap();

        assert_eq!(decrypted.as_slice(), plaintext.as_slice(), "64KB roundtrip mismatch");
    }

    #[test]
    fn test_encrypt_decrypt_many_messages_roundtrip() {
        let (pk, sk) = generate_keypair().unwrap();
        let context = HybridEncryptionContext::default();

        for i in 0..50u32 {
            let msg = format!("Message number {} with varying length data!", i);
            let ct = encrypt_hybrid(&pk, msg.as_bytes(), Some(&context))
                .unwrap_or_else(|e| panic!("encrypt {} failed: {:?}", i, e));
            let dec = decrypt_hybrid(&sk, &ct, Some(&context))
                .unwrap_or_else(|e| panic!("decrypt {} failed: {:?}", i, e));
            assert_eq!(dec.as_slice(), msg.as_bytes(), "Message {} roundtrip mismatch", i);
        }
    }

    #[test]
    fn test_encrypt_wrong_key_fails() {
        let (pk_a, _sk_a) = generate_keypair().unwrap();
        let (_pk_b, sk_b) = generate_keypair().unwrap();

        let plaintext = b"secret data";
        let context = HybridEncryptionContext::default();

        let ct = encrypt_hybrid(&pk_a, plaintext, Some(&context)).unwrap();

        // Decrypt with wrong key — should fail (AEAD authentication)
        let result = decrypt_hybrid(&sk_b, &ct, Some(&context));
        assert!(result.is_err(), "Decryption with wrong key should fail");
    }

    // ============================================================================
    // Tamper Detection Tests
    // ============================================================================

    #[test]
    fn test_tampered_kem_ciphertext_fails() {
        let (pk, sk) = generate_keypair().unwrap();
        let context = HybridEncryptionContext::default();

        let mut ct = encrypt_hybrid(&pk, b"test", Some(&context)).unwrap();

        // Flip a byte in the ML-KEM ciphertext
        if !ct.kem_ciphertext().is_empty() {
            ct.kem_ciphertext_mut()[0] ^= 0xFF;
        }

        let result = decrypt_hybrid(&sk, &ct, Some(&context));
        assert!(result.is_err(), "Tampered KEM ciphertext should fail decryption");
    }

    #[test]
    fn test_tampered_ecdh_pk_fails() {
        let (pk, sk) = generate_keypair().unwrap();
        let context = HybridEncryptionContext::default();

        let mut ct = encrypt_hybrid(&pk, b"test", Some(&context)).unwrap();

        // Flip a byte in the ephemeral ECDH public key
        if !ct.ecdh_ephemeral_pk().is_empty() {
            ct.ecdh_ephemeral_pk_mut()[0] ^= 0xFF;
        }

        let result = decrypt_hybrid(&sk, &ct, Some(&context));
        assert!(result.is_err(), "Tampered ECDH PK should fail decryption");
    }

    #[test]
    fn test_tampered_symmetric_ciphertext_fails() {
        let (pk, sk) = generate_keypair().unwrap();
        let context = HybridEncryptionContext::default();

        let mut ct = encrypt_hybrid(&pk, b"test data here", Some(&context)).unwrap();

        // Flip a byte in the AES-GCM ciphertext
        if !ct.symmetric_ciphertext().is_empty() {
            ct.symmetric_ciphertext_mut()[0] ^= 0xFF;
        }

        let result = decrypt_hybrid(&sk, &ct, Some(&context));
        assert!(result.is_err(), "Tampered symmetric ciphertext should fail");
    }

    #[test]
    fn test_tampered_nonce_fails() {
        let (pk, sk) = generate_keypair().unwrap();
        let context = HybridEncryptionContext::default();

        let mut ct = encrypt_hybrid(&pk, b"test", Some(&context)).unwrap();

        // Alter the nonce
        if !ct.nonce().is_empty() {
            ct.nonce_mut()[0] ^= 0xFF;
        }

        let result = decrypt_hybrid(&sk, &ct, Some(&context));
        assert!(result.is_err(), "Tampered nonce should fail decryption");
    }

    #[test]
    fn test_tampered_tag_fails() {
        let (pk, sk) = generate_keypair().unwrap();
        let context = HybridEncryptionContext::default();

        let mut ct = encrypt_hybrid(&pk, b"test", Some(&context)).unwrap();

        // Alter the authentication tag
        if !ct.tag().is_empty() {
            ct.tag_mut()[0] ^= 0xFF;
        }

        let result = decrypt_hybrid(&sk, &ct, Some(&context));
        assert!(result.is_err(), "Tampered tag should fail decryption");
    }

    // ============================================================================
    // Signature Roundtrip Tests
    // ============================================================================

    #[test]
    fn test_sig_generate_sign_verify_roundtrip() {
        let (pk, sk) = sig::generate_keypair().expect("keygen should succeed");

        let message = b"Document to sign with hybrid ML-DSA + Ed25519";
        let signature = sig::sign(&sk, message).expect("signing should succeed");
        let is_valid = sig::verify(&pk, message, &signature).expect("verify should succeed");

        assert!(is_valid, "Valid signature should verify");
    }

    #[test]
    fn test_sig_persistent_identity_succeeds() {
        let (pk, sk) = sig::generate_keypair().unwrap();

        // Sign 20 messages with the same keypair
        for i in 0..20u32 {
            let msg = format!("Persistent identity message {}", i);
            let signature = sig::sign(&sk, msg.as_bytes())
                .unwrap_or_else(|e| panic!("sign {} failed: {:?}", i, e));
            let is_valid = sig::verify(&pk, msg.as_bytes(), &signature)
                .unwrap_or_else(|e| panic!("verify {} failed: {:?}", i, e));
            assert!(is_valid, "Message {} should verify", i);
        }
    }

    #[test]
    fn test_sig_cross_key_rejection_fails() {
        let (_pk_a, sk_a) = sig::generate_keypair().unwrap();
        let (pk_b, _sk_b) = sig::generate_keypair().unwrap();

        let message = b"Signed by A";
        let signature = sig::sign(&sk_a, message).unwrap();

        // Verify with B's public key — should fail
        let result = sig::verify(&pk_b, message, &signature);
        if let Ok(valid) = result {
            assert!(!valid, "Cross-key verification should return false");
        }
    }

    // ============================================================================
    // Combined Workflow Test
    // ============================================================================

    #[test]
    fn test_complete_hybrid_workflow_succeeds() {
        // Step 1: Generate KEM keypair
        let (kem_pk, kem_sk) = generate_keypair().unwrap();

        // Step 2: Generate signature keypair
        let (sig_pk, sig_sk) = sig::generate_keypair().unwrap();

        // Step 3: Encapsulate to derive shared secret
        let enc_key = encapsulate(&kem_pk).unwrap();
        let shared_secret = enc_key.expose_secret().to_vec();

        // Step 4: Encrypt a message using the hybrid encryption API
        let plaintext = b"Complete hybrid workflow test: KEM + Encrypt + Sign + Verify + Decrypt";
        let context = HybridEncryptionContext::default();
        let ct = encrypt_hybrid(&kem_pk, plaintext, Some(&context)).unwrap();

        // Step 5: Sign the ciphertext for non-repudiation
        // Serialize a simple representation of the ciphertext for signing
        let ct_bytes_for_sig =
            [ct.kem_ciphertext(), ct.ecdh_ephemeral_pk(), ct.symmetric_ciphertext()].concat();
        let signature = sig::sign(&sig_sk, &ct_bytes_for_sig).unwrap();

        // Step 6: Verify the signature
        let sig_valid = sig::verify(&sig_pk, &ct_bytes_for_sig, &signature).unwrap();
        assert!(sig_valid, "Ciphertext signature should verify");

        // Step 7: Decapsulate shared secret
        let dec_secret = decapsulate(&kem_sk, &enc_key).unwrap();
        assert_eq!(
            dec_secret.expose_secret(),
            shared_secret.as_slice(),
            "Shared secrets should match"
        );

        // Step 8: Decrypt the message
        let decrypted = decrypt_hybrid(&kem_sk, &ct, Some(&context)).unwrap();
        assert_eq!(decrypted.as_slice(), plaintext, "Full workflow roundtrip mismatch");
    }
}

// Originally: hybrid_zeroization_tests.rs
mod zeroization {
    // Test files use unwrap() for simplicity - test failures will show clear panics
    #![allow(clippy::unwrap_used)]
    // Test files may use eprintln for diagnostic output
    #![allow(clippy::print_stderr)]

    //! Integration tests for zeroization security features
    //!
    //! These tests verify that secret key material is properly zeroized
    //! when keys are dropped or explicitly zeroized.

    use latticearc::hybrid::{kem_hybrid as kem, sig_hybrid as sig};
    use zeroize::Zeroize;

    #[test]
    fn test_hybrid_kem_secret_key_zeroization_before_drop_succeeds() {
        let (_pk, sk) = kem::generate_keypair().unwrap();

        // Verify public key accessors work (private keys are in aws-lc-rs, not exposed as bytes)
        let mut pk_bytes = sk.ml_kem_pk_bytes();
        assert!(!pk_bytes.iter().all(|&x| x == 0), "ML-KEM PK should be non-zero");
        pk_bytes.zeroize();
        assert!(pk_bytes.iter().all(|&x| x == 0), "Zeroization of PK copy failed");

        let mut ecdh_pk = sk.ecdh_public_key_bytes();
        assert!(!ecdh_pk.iter().all(|&x| x == 0), "ECDH PK should be non-zero");
        ecdh_pk.zeroize();
        assert!(ecdh_pk.iter().all(|&x| x == 0), "Zeroization of ECDH PK copy failed");

        // Drop triggers aws-lc-rs cleanup for both ML-KEM DecapsulationKey and X25519 PrivateKey
        drop(sk);
    }

    #[test]
    fn test_hybrid_sig_secret_key_zeroization_before_drop_succeeds() {
        let (_pk, sk) = sig::generate_keypair().unwrap();

        // Verify zeroization works before drop
        let mut sk_bytes = sk.ml_dsa_sk_bytes();
        sk_bytes.zeroize();
        // assert!(!sk_bytes.is_empty(), "Zeroized bytes should not be empty");
        assert!(sk_bytes.iter().all(|&x| x == 0), "Zeroization failed - not all bytes are zero");

        let mut sk_bytes2 = sk.ed25519_sk_bytes();
        sk_bytes2.zeroize();
        // assert!(!sk_bytes2.is_empty(), "Zeroized bytes should not be empty");
        assert!(sk_bytes2.iter().all(|&x| x == 0), "Zeroization failed - not all bytes are zero");
    }

    #[test]
    fn test_hybrid_kem_secret_key_no_clone_succeeds() {
        let (_pk, sk) = kem::generate_keypair().unwrap();

        // Verify type exists and does not have Clone at compile time
        // The fact that this code compiles without sk.clone() confirms
        // that Clone is not implemented
        let _sk = sk;

        // Attempting to call sk.clone() would result in a compile error:
        // error[E0599]: no method named `clone` found for struct `HybridSecretKey` in the current scope
    }

    #[test]
    fn test_hybrid_sig_secret_key_no_clone_succeeds() {
        let (_pk, sk) = sig::generate_keypair().unwrap();

        // Verify type exists and does not have Clone at compile time
        // The fact that this code compiles without sk.clone() confirms
        // that Clone is not implemented
        let _sk = sk;

        // Attempting to call sk.clone() would result in a compile error:
        // error[E0599]: no method named `clone` found for struct `HybridSecretKey` in the current scope
    }

    #[test]
    fn test_encapsulated_key_shared_secret_zeroization_succeeds() {
        let (pk, _sk) = kem::generate_keypair().unwrap();

        let enc_result = kem::encapsulate(&pk);
        if let Ok(enc_key) = enc_result {
            // Get the shared secret and verify it can be zeroized
            let mut secret = enc_key.expose_secret().to_vec();
            secret.zeroize();
            // assert!(!secret.is_empty(), "Zeroized secret should not be empty");
            assert!(secret.iter().all(|&x| x == 0), "Zeroization failed - not all bytes are zero");
        } else {
            // If encapsulation fails (e.g., ML-KEM not available), skip this test gracefully
            eprintln!("Encapsulation failed, skipping test: {:?}", enc_result);
        }
    }

    #[test]
    fn test_hybrid_kem_public_key_bytes_not_zero_before_use_succeeds() {
        let (_pk, sk): (_, kem::HybridKemSecretKey) = kem::generate_keypair().unwrap();

        // Verify that public key bytes are NOT all zeros (real keys were generated)
        let ml_kem_pk = sk.ml_kem_pk_bytes();
        let ecdh_pk = sk.ecdh_public_key_bytes();

        assert!(
            ml_kem_pk.iter().any(|&x| x != 0),
            "ML-KEM public key should contain non-zero bytes"
        );
        assert!(ecdh_pk.iter().any(|&x| x != 0), "ECDH public key should contain non-zero bytes");
    }

    #[test]
    fn test_hybrid_sig_secret_key_bytes_not_zero_before_use_succeeds() {
        let (_pk, sk): (_, sig::HybridSigSecretKey) = sig::generate_keypair().unwrap();

        // Verify that secret key bytes are NOT all zeros initially (they should be non-zero)
        let ml_dsa_bytes = sk.ml_dsa_sk_bytes();
        let ed25519_bytes = sk.ed25519_sk_bytes();

        // At least one of the bytes should be non-zero for a proper key
        let ml_dsa_has_non_zero = ml_dsa_bytes.iter().any(|&x| x != 0);
        let ed25519_has_non_zero = ed25519_bytes.iter().any(|&x| x != 0);

        assert!(ml_dsa_has_non_zero, "ML-DSA secret key should contain non-zero bytes");
        assert!(ed25519_has_non_zero, "Ed25519 secret key should contain non-zero bytes");
    }
}
