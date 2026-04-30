//! Hybrid encryption primitives tests.
#![deny(unsafe_code)]

// Originally: hybrid_encrypt_hybrid_coverage.rs
mod hybrid {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]
    #![allow(clippy::indexing_slicing)]
    #![allow(clippy::print_stderr)]
    #![allow(clippy::cast_possible_truncation)]
    #![allow(missing_docs)]
    //! Coverage tests for encrypt_hybrid.rs
    //!
    //! Targets uncovered error paths, validation branches, and edge cases
    //! in the hybrid encryption module.

    use latticearc::hybrid::encrypt_hybrid::{
        DerivationBinding, HybridCiphertext, HybridEncryptionContext, HybridEncryptionError,
        decrypt_hybrid, derive_encryption_key, encrypt_hybrid,
    };
    use latticearc::hybrid::kem_hybrid::generate_keypair;

    // ============================================================================
    // derive_encryption_key error paths
    // ============================================================================

    #[test]
    fn test_derive_key_rejects_too_short_secret_fails() {
        let ctx = HybridEncryptionContext::default();
        let short_secret = vec![0u8; 16];
        let result = derive_encryption_key(&short_secret, &ctx, &DerivationBinding::empty());
        assert!(result.is_err());
        match result.unwrap_err() {
            HybridEncryptionError::KdfError(msg) => {
                assert!(msg.contains("32 bytes"));
            }
            other => panic!("Expected KdfError, got {:?}", other),
        }
    }

    #[test]
    fn test_derive_key_rejects_31_byte_secret_fails() {
        let ctx = HybridEncryptionContext::default();
        let secret = vec![0u8; 31];
        assert!(derive_encryption_key(&secret, &ctx, &DerivationBinding::empty()).is_err());
    }

    #[test]
    fn test_derive_key_rejects_33_byte_secret_fails() {
        let ctx = HybridEncryptionContext::default();
        let secret = vec![0u8; 33];
        assert!(derive_encryption_key(&secret, &ctx, &DerivationBinding::empty()).is_err());
    }

    #[test]
    fn test_derive_key_rejects_65_byte_secret_fails() {
        let ctx = HybridEncryptionContext::default();
        let secret = vec![0u8; 65];
        assert!(derive_encryption_key(&secret, &ctx, &DerivationBinding::empty()).is_err());
    }

    #[test]
    fn test_derive_key_rejects_empty_secret_fails() {
        let ctx = HybridEncryptionContext::default();
        let secret = vec![];
        assert!(derive_encryption_key(&secret, &ctx, &DerivationBinding::empty()).is_err());
    }

    #[test]
    fn test_derive_key_accepts_32_byte_secret_succeeds() {
        let ctx = HybridEncryptionContext::default();
        let secret = vec![0xABu8; 32];
        let result = derive_encryption_key(&secret, &ctx, &DerivationBinding::empty());
        assert!(result.is_ok());
        let key = result.unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_derive_key_accepts_64_byte_secret_succeeds() {
        let ctx = HybridEncryptionContext::default();
        let secret = vec![0xCDu8; 64];
        let result = derive_encryption_key(&secret, &ctx, &DerivationBinding::empty());
        assert!(result.is_ok());
        let key = result.unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_derive_key_deterministic_is_deterministic() {
        let ctx = HybridEncryptionContext::default();
        let secret = vec![42u8; 32];
        let key1 = derive_encryption_key(&secret, &ctx, &DerivationBinding::empty()).unwrap();
        let key2 = derive_encryption_key(&secret, &ctx, &DerivationBinding::empty()).unwrap();
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_derive_key_different_secrets_produce_different_keys_succeeds() {
        let ctx = HybridEncryptionContext::default();
        let secret_a = vec![1u8; 32];
        let secret_b = vec![2u8; 32];
        let key_a = derive_encryption_key(&secret_a, &ctx, &DerivationBinding::empty()).unwrap();
        let key_b = derive_encryption_key(&secret_b, &ctx, &DerivationBinding::empty()).unwrap();
        assert_ne!(key_a, key_b);
    }

    #[test]
    fn test_derive_key_different_context_produces_different_key_succeeds() {
        let ctx_a = HybridEncryptionContext::with_explicit_info(b"context-A", vec![]);
        let ctx_b = HybridEncryptionContext::with_explicit_info(b"context-B", vec![]);
        let secret = vec![99u8; 32];
        let key_a = derive_encryption_key(&secret, &ctx_a, &DerivationBinding::empty()).unwrap();
        let key_b = derive_encryption_key(&secret, &ctx_b, &DerivationBinding::empty()).unwrap();
        assert_ne!(key_a, key_b);
    }

    #[test]
    fn test_derive_key_with_aad_succeeds() {
        let ctx_no_aad = HybridEncryptionContext::with_explicit_info(b"test", vec![]);
        let ctx_with_aad =
            HybridEncryptionContext::with_explicit_info(b"test", b"extra-data".to_vec());
        let secret = vec![77u8; 32];
        let key_no =
            derive_encryption_key(&secret, &ctx_no_aad, &DerivationBinding::empty()).unwrap();
        let key_with =
            derive_encryption_key(&secret, &ctx_with_aad, &DerivationBinding::empty()).unwrap();
        assert_ne!(key_no, key_with);
    }

    // ============================================================================
    // decrypt_hybrid() validation error paths
    // ============================================================================

    // Pattern 6 (#51): decrypt_hybrid collapses every component-shape error
    // into the opaque DecryptionError so attackers cannot tell which field
    // (KEM CT, ECDH PK, nonce, or tag) was the malformed one. Tests below
    // therefore assert only the surviving variant — not the message contents.

    #[test]
    fn test_decrypt_hybrid_rejects_wrong_kem_ct_size_fails() {
        let (_pk, sk) = generate_keypair().unwrap();
        let ct = HybridCiphertext::new(
            vec![0u8; 500], // Should be 1088
            vec![0u8; 32],
            vec![0u8; 32],
            vec![0u8; 12],
            vec![0u8; 16],
        );
        let result = decrypt_hybrid(&sk, &ct, None);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), HybridEncryptionError::DecryptionError(_)));
    }

    #[test]
    fn test_decrypt_hybrid_rejects_wrong_ecdh_pk_size_fails() {
        let (_pk, sk) = generate_keypair().unwrap();
        let ct = HybridCiphertext::new(
            vec![0u8; 1088],
            vec![0u8; 16], // Should be 32
            vec![0u8; 32],
            vec![0u8; 12],
            vec![0u8; 16],
        );
        let result = decrypt_hybrid(&sk, &ct, None);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), HybridEncryptionError::DecryptionError(_)));
    }

    #[test]
    fn test_decrypt_hybrid_rejects_wrong_nonce_size_fails() {
        let (_pk, sk) = generate_keypair().unwrap();
        let ct = HybridCiphertext::new(
            vec![0u8; 1088],
            vec![0u8; 32],
            vec![0u8; 32],
            vec![0u8; 8], // Should be 12
            vec![0u8; 16],
        );
        let result = decrypt_hybrid(&sk, &ct, None);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), HybridEncryptionError::DecryptionError(_)));
    }

    #[test]
    fn test_decrypt_hybrid_rejects_wrong_tag_size_fails() {
        let (_pk, sk) = generate_keypair().unwrap();
        let ct = HybridCiphertext::new(
            vec![0u8; 1088],
            vec![0u8; 32],
            vec![0u8; 32],
            vec![0u8; 12],
            vec![0u8; 4], // Should be 16
        );
        let result = decrypt_hybrid(&sk, &ct, None);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), HybridEncryptionError::DecryptionError(_)));
    }

    // ============================================================================
    // HybridEncryptionError Display coverage
    // ============================================================================

    #[test]
    fn test_error_display_kem_error_fails() {
        let err = HybridEncryptionError::KemError("test kem".to_string());
        let msg = format!("{}", err);
        assert!(msg.contains("KEM error"));
        assert!(msg.contains("test kem"));
    }

    #[test]
    fn test_error_display_encryption_error_fails() {
        let err = HybridEncryptionError::EncryptionError("test enc".to_string());
        let msg = format!("{}", err);
        assert!(msg.contains("Encryption error"));
    }

    #[test]
    fn test_error_display_decryption_error_fails() {
        let err = HybridEncryptionError::DecryptionError("test dec".to_string());
        let msg = format!("{}", err);
        assert!(msg.contains("Decryption error"));
    }

    #[test]
    fn test_error_display_kdf_error_fails() {
        let err = HybridEncryptionError::KdfError("test kdf".to_string());
        let msg = format!("{}", err);
        assert!(msg.contains("Key derivation error"));
    }

    #[test]
    fn test_error_display_invalid_input_fails() {
        let err = HybridEncryptionError::InvalidInput("test input".to_string());
        let msg = format!("{}", err);
        assert!(msg.contains("Invalid input"));
    }

    #[test]
    fn test_error_display_key_length_error_fails() {
        let err = HybridEncryptionError::KeyLengthError { expected: 32, actual: 16 };
        let msg = format!("{}", err);
        assert!(msg.contains("32"));
        assert!(msg.contains("16"));
    }

    // ============================================================================
    // HybridEncryptionContext coverage
    // ============================================================================

    #[test]
    fn test_default_context_succeeds() {
        let ctx = HybridEncryptionContext::default();
        assert_eq!(ctx.info(), b"LatticeArc-Hybrid-Encryption-v1");
        assert!(ctx.aad.is_empty());
    }

    #[test]
    fn test_custom_context_succeeds() {
        let ctx =
            HybridEncryptionContext::with_explicit_info(b"custom-info", b"custom-aad".to_vec());
        assert_eq!(ctx.info(), b"custom-info");
        assert_eq!(ctx.aad, b"custom-aad");
    }

    #[test]
    fn test_with_aad_uses_canonical_info_label() {
        // `with_aad` is the recommended constructor for per-message AAD
        // without overriding the protocol domain separator. It MUST set
        // `info` to the canonical `HYBRID_ENCRYPTION_INFO` constant so that
        // ciphertexts produced through this path are interoperable with
        // those produced via `default()`.
        let ctx = HybridEncryptionContext::with_aad(b"per-message-aad".to_vec());
        assert_eq!(
            ctx.info(),
            b"LatticeArc-Hybrid-Encryption-v1",
            "with_aad must use the canonical HYBRID_ENCRYPTION_INFO label"
        );
        assert_eq!(ctx.aad, b"per-message-aad");
    }

    #[test]
    fn test_with_aad_aad_value_flows_into_key_derivation() {
        use latticearc::hybrid::encrypt_hybrid::derive_encryption_key;

        let ctx_aad_a = HybridEncryptionContext::with_aad(b"aad-a".to_vec());
        let ctx_aad_b = HybridEncryptionContext::with_aad(b"aad-b".to_vec());

        let secret = vec![0x42u8; 32];
        let key_a =
            derive_encryption_key(&secret, &ctx_aad_a, &DerivationBinding::empty()).unwrap();
        let key_b =
            derive_encryption_key(&secret, &ctx_aad_b, &DerivationBinding::empty()).unwrap();

        assert_ne!(
            key_a.as_slice(),
            key_b.as_slice(),
            "AAD value must influence the derived encryption key"
        );
    }

    #[test]
    fn test_with_aad_empty_aad_matches_default() {
        // `with_aad(vec![])` should be observationally identical to
        // `default()` — same info, same AAD. Documents the equivalence.
        let ctx_default = HybridEncryptionContext::default();
        let ctx_empty_aad = HybridEncryptionContext::with_aad(vec![]);
        assert_eq!(ctx_default.info(), ctx_empty_aad.info());
        assert_eq!(ctx_default.aad, ctx_empty_aad.aad);
    }

    // ============================================================================
    // HybridCiphertext coverage
    // ============================================================================

    #[test]
    fn test_ciphertext_clone_and_debug_succeeds() {
        let ct = HybridCiphertext::new(
            vec![1, 2, 3],
            vec![4, 5],
            vec![6, 7, 8],
            vec![9, 10],
            vec![11, 12],
        );
        let cloned = ct.clone();
        assert_eq!(cloned.kem_ciphertext(), ct.kem_ciphertext());
        assert_eq!(cloned.ecdh_ephemeral_pk(), ct.ecdh_ephemeral_pk());
        assert_eq!(cloned.symmetric_ciphertext(), ct.symmetric_ciphertext());
        assert_eq!(cloned.nonce(), ct.nonce());
        assert_eq!(cloned.tag(), ct.tag());

        let debug = format!("{:?}", ct);
        assert!(debug.contains("HybridCiphertext"));
    }

    // ============================================================================
    // encrypt_hybrid / decrypt_hybrid with custom context
    // ============================================================================

    #[test]
    fn test_encrypt_decrypt_hybrid_with_custom_context_roundtrip() {
        let (pk, sk) = generate_keypair().unwrap();
        let plaintext = b"test with custom context and AAD";

        let ctx = HybridEncryptionContext::with_explicit_info(
            b"custom-app-v2",
            b"associated-data-123".to_vec(),
        );

        let ct = encrypt_hybrid(&pk, plaintext, Some(&ctx)).unwrap();
        assert!(!ct.symmetric_ciphertext().is_empty());
        assert_eq!(ct.nonce().len(), 12);
        assert_eq!(ct.tag().len(), 16);
        assert_eq!(ct.ecdh_ephemeral_pk().len(), 32);
        assert_eq!(ct.kem_ciphertext().len(), 1088);

        let decrypted = decrypt_hybrid(&sk, &ct, Some(&ctx)).unwrap();
        assert_eq!(decrypted.as_slice(), plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_hybrid_without_context_roundtrip() {
        let (pk, sk) = generate_keypair().unwrap();
        let plaintext = b"no context provided";

        let ct = encrypt_hybrid(&pk, plaintext, None).unwrap();
        let decrypted = decrypt_hybrid(&sk, &ct, None).unwrap();
        assert_eq!(decrypted.as_slice(), plaintext);
    }

    #[test]
    fn test_encrypt_hybrid_empty_plaintext_succeeds() {
        let (pk, sk) = generate_keypair().unwrap();
        let plaintext = b"";

        let ct = encrypt_hybrid(&pk, plaintext, None).unwrap();
        let decrypted = decrypt_hybrid(&sk, &ct, None).unwrap();
        assert_eq!(decrypted.as_slice(), plaintext);
    }

    #[test]
    fn test_encrypt_hybrid_large_plaintext_succeeds() {
        let (pk, sk) = generate_keypair().unwrap();
        let plaintext = vec![0xAAu8; 65536]; // 64KB

        let ct = encrypt_hybrid(&pk, &plaintext, None).unwrap();
        let decrypted = decrypt_hybrid(&sk, &ct, None).unwrap();
        assert_eq!(decrypted.as_slice(), plaintext);
    }

    // ============================================================================
    // Tamper detection for hybrid path
    // ============================================================================

    #[test]
    fn test_decrypt_hybrid_tampered_ciphertext_fails() {
        let (pk, sk) = generate_keypair().unwrap();
        let plaintext = b"tamper test";

        let mut ct = encrypt_hybrid(&pk, plaintext, None).unwrap();
        // Flip a byte in symmetric ciphertext
        if let Some(byte) = ct.symmetric_ciphertext_mut().first_mut() {
            *byte ^= 0xFF;
        }

        let result = decrypt_hybrid(&sk, &ct, None);
        assert!(result.is_err(), "Tampered ciphertext should fail decryption");
    }

    #[test]
    fn test_decrypt_hybrid_wrong_context_fails() {
        let (pk, sk) = generate_keypair().unwrap();
        let plaintext = b"context mismatch test";

        let ctx_enc = HybridEncryptionContext::with_explicit_info(b"encrypt-ctx", vec![]);
        let ctx_dec = HybridEncryptionContext::with_explicit_info(b"decrypt-ctx", vec![]);

        let ct = encrypt_hybrid(&pk, plaintext, Some(&ctx_enc)).unwrap();
        let result = decrypt_hybrid(&sk, &ct, Some(&ctx_dec));
        assert!(result.is_err(), "Wrong context should fail");
    }

    // ============================================================================
    // encrypt() / decrypt() error path: encrypt succeeds but decrypt
    // fails due to ML-KEM decapsulation limitation
    // ============================================================================

    // ============================================================================
    // Error equality and Debug
    // ============================================================================

    #[test]
    fn test_error_clone_round_trips() {
        let err1 = HybridEncryptionError::KemError("a".to_string());
        let err2 = err1.clone();
        assert_eq!(err1.to_string(), err2.to_string());
        assert!(matches!(err2, HybridEncryptionError::KemError(_)));

        let err3 = HybridEncryptionError::KemError("b".to_string());
        assert_ne!(err1.to_string(), err3.to_string());

        let err4 = HybridEncryptionError::EncryptionError("a".to_string());
        assert!(matches!(err4, HybridEncryptionError::EncryptionError(_)));
    }

    #[test]
    fn test_error_debug_fails() {
        let err = HybridEncryptionError::KeyLengthError { expected: 32, actual: 0 };
        let debug = format!("{:?}", err);
        assert!(debug.contains("KeyLengthError"));
    }

    #[test]
    fn test_context_clone_and_debug_succeeds() {
        let ctx = HybridEncryptionContext::default();
        let cloned = ctx.clone();
        assert_eq!(cloned.info(), ctx.info());

        let debug = format!("{:?}", ctx);
        assert!(debug.contains("HybridEncryptionContext"));
    }
}

// Originally: hybrid_encrypt_hybrid_validation.rs
mod validation {
    //! Coverage tests for encrypt_hybrid.rs decrypt validation paths
    //! Tests validation errors that don't require actual ML-KEM decapsulation.

    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic)]

    use latticearc::hybrid::encrypt_hybrid::{
        HybridCiphertext, HybridEncryptionContext, HybridEncryptionError,
    };

    #[test]
    fn test_hybrid_ciphertext_clone_debug_succeeds() {
        let ct = HybridCiphertext::new(
            vec![1, 2, 3],
            vec![4, 5],
            vec![6, 7, 8],
            vec![9, 10],
            vec![11, 12],
        );
        let cloned = ct.clone();
        assert_eq!(cloned.kem_ciphertext(), ct.kem_ciphertext());
        let debug = format!("{:?}", ct);
        assert!(debug.contains("HybridCiphertext"));
    }

    #[test]
    fn test_hybrid_encryption_context_clone_debug_succeeds() {
        let ctx = HybridEncryptionContext::with_explicit_info(b"info", b"aad".to_vec());
        let cloned = ctx.clone();
        assert_eq!(cloned.info(), ctx.info());
        let debug = format!("{:?}", ctx);
        assert!(debug.contains("HybridEncryptionContext"));

        let default = HybridEncryptionContext::default();
        assert!(!default.info().is_empty());
    }

    #[test]
    fn test_hybrid_encryption_error_display_fails() {
        let e1 = HybridEncryptionError::KemError("test".to_string());
        assert!(e1.to_string().contains("test"));

        let e2 = HybridEncryptionError::EncryptionError("enc".to_string());
        assert!(e2.to_string().contains("enc"));

        let e3 = HybridEncryptionError::DecryptionError("dec".to_string());
        assert!(e3.to_string().contains("dec"));

        let e4 = HybridEncryptionError::KdfError("kdf".to_string());
        assert!(e4.to_string().contains("kdf"));

        let e5 = HybridEncryptionError::InvalidInput("invalid".to_string());
        assert!(e5.to_string().contains("invalid"));

        let e6 = HybridEncryptionError::KeyLengthError { expected: 32, actual: 16 };
        assert!(e6.to_string().contains("32"));
        assert!(e6.to_string().contains("16"));

        let e1_clone = e1.clone();
        assert_eq!(e1.to_string(), e1_clone.to_string());
        assert!(matches!(e1, HybridEncryptionError::KemError(_)));
        assert!(matches!(e2, HybridEncryptionError::EncryptionError(_)));
    }
}

// Originally: hybrid_encrypt_true_coverage.rs
mod true_hybrid {
    //! Coverage tests for encrypt_hybrid.rs — true hybrid (ML-KEM + X25519)
    //! encrypt/decrypt roundtrip and error paths.

    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic,
        clippy::arithmetic_side_effects,
        clippy::cast_precision_loss
    )]
    use latticearc::hybrid::encrypt_hybrid::{
        HybridCiphertext, HybridEncryptionContext, decrypt_hybrid, encrypt_hybrid,
    };
    use latticearc::hybrid::kem_hybrid;

    // ============================================================
    // True hybrid encrypt/decrypt roundtrip
    // ============================================================

    #[test]
    fn test_true_hybrid_encrypt_decrypt_roundtrip() {
        let (hybrid_pk, hybrid_sk) = kem_hybrid::generate_keypair().unwrap();

        let plaintext = b"True hybrid encryption roundtrip test";
        let ct = encrypt_hybrid(&hybrid_pk, plaintext, None).unwrap();

        assert_eq!(ct.kem_ciphertext().len(), 1088, "ML-KEM-768 ciphertext");
        assert_eq!(ct.ecdh_ephemeral_pk().len(), 32, "X25519 ephemeral pk");
        assert_eq!(ct.nonce().len(), 12, "AES-GCM nonce");
        assert_eq!(ct.tag().len(), 16, "AES-GCM tag");
        assert!(!ct.symmetric_ciphertext().is_empty());

        let decrypted = decrypt_hybrid(&hybrid_sk, &ct, None).unwrap();
        assert_eq!(decrypted.as_slice(), plaintext.as_slice());
    }

    #[test]
    fn test_true_hybrid_encrypt_decrypt_with_context_roundtrip() {
        let (hybrid_pk, hybrid_sk) = kem_hybrid::generate_keypair().unwrap();

        let plaintext = b"True hybrid with custom context";
        let ctx = HybridEncryptionContext::with_explicit_info(
            b"LatticeArc-Test-v1",
            b"additional-auth-data".to_vec(),
        );

        let ct = encrypt_hybrid(&hybrid_pk, plaintext, Some(&ctx)).unwrap();
        let decrypted = decrypt_hybrid(&hybrid_sk, &ct, Some(&ctx)).unwrap();
        assert_eq!(decrypted.as_slice(), plaintext.as_slice());
    }

    #[test]
    fn test_true_hybrid_encrypt_empty_plaintext_succeeds() {
        let (hybrid_pk, hybrid_sk) = kem_hybrid::generate_keypair().unwrap();

        let plaintext = b"";
        let ct = encrypt_hybrid(&hybrid_pk, plaintext, None).unwrap();
        let decrypted = decrypt_hybrid(&hybrid_sk, &ct, None).unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn test_true_hybrid_decrypt_wrong_aad_fails() {
        let (hybrid_pk, hybrid_sk) = kem_hybrid::generate_keypair().unwrap();

        let ctx1 = HybridEncryptionContext::with_explicit_info(
            b"LatticeArc-Test-v1",
            b"correct-aad".to_vec(),
        );
        let ctx2 = HybridEncryptionContext::with_explicit_info(
            b"LatticeArc-Test-v1",
            b"wrong-aad".to_vec(),
        );

        let plaintext = b"AAD mismatch test";
        let ct = encrypt_hybrid(&hybrid_pk, plaintext, Some(&ctx1)).unwrap();
        let result = decrypt_hybrid(&hybrid_sk, &ct, Some(&ctx2));
        assert!(result.is_err(), "Decryption with wrong AAD should fail");
    }

    // ============================================================
    // decrypt_hybrid error paths (bad ciphertext structure)
    // ============================================================

    #[test]
    fn test_decrypt_hybrid_bad_kem_ciphertext_length_fails() {
        let (_hybrid_pk, hybrid_sk) = kem_hybrid::generate_keypair().unwrap();

        let bad_ct = HybridCiphertext::new(
            vec![0u8; 100], // wrong length, expect 1088
            vec![0u8; 32],
            vec![0u8; 16],
            vec![0u8; 12],
            vec![0u8; 16],
        );
        let result = decrypt_hybrid(&hybrid_sk, &bad_ct, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_hybrid_bad_ecdh_pk_length_fails() {
        let (_hybrid_pk, hybrid_sk) = kem_hybrid::generate_keypair().unwrap();

        let bad_ct = HybridCiphertext::new(
            vec![0u8; 1088],
            vec![0u8; 10], // wrong length, expect 32
            vec![0u8; 16],
            vec![0u8; 12],
            vec![0u8; 16],
        );
        let result = decrypt_hybrid(&hybrid_sk, &bad_ct, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_hybrid_bad_nonce_length_fails() {
        let (_hybrid_pk, hybrid_sk) = kem_hybrid::generate_keypair().unwrap();

        let bad_ct = HybridCiphertext::new(
            vec![0u8; 1088],
            vec![0u8; 32],
            vec![0u8; 16],
            vec![0u8; 5], // wrong length, expect 12
            vec![0u8; 16],
        );
        let result = decrypt_hybrid(&hybrid_sk, &bad_ct, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_hybrid_bad_tag_length_fails() {
        let (_hybrid_pk, hybrid_sk) = kem_hybrid::generate_keypair().unwrap();

        let bad_ct = HybridCiphertext::new(
            vec![0u8; 1088],
            vec![0u8; 32],
            vec![0u8; 16],
            vec![0u8; 12],
            vec![0u8; 5], // wrong length, expect 16
        );
        let result = decrypt_hybrid(&hybrid_sk, &bad_ct, None);
        assert!(result.is_err());
    }
}
