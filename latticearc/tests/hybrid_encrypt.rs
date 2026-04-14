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
    // Legacy `encrypt`/`decrypt` are deprecated; the tests below intentionally exercise
    // them to preserve coverage of the legacy ML-KEM-only code path.
    #![allow(deprecated)]

    //! Coverage tests for encrypt_hybrid.rs
    //!
    //! Targets uncovered error paths, validation branches, and edge cases
    //! in the hybrid encryption module.

    use latticearc::hybrid::encrypt_hybrid::{
        HybridCiphertext, HybridEncryptionContext, HybridEncryptionError, decrypt, decrypt_hybrid,
        derive_encryption_key, encrypt, encrypt_hybrid,
    };
    use latticearc::hybrid::kem_hybrid::generate_keypair;

    // ============================================================================
    // derive_encryption_key error paths
    // ============================================================================

    #[test]
    fn test_derive_key_rejects_too_short_secret_fails() {
        let ctx = HybridEncryptionContext::default();
        let short_secret = vec![0u8; 16];
        let result = derive_encryption_key(&short_secret, &ctx);
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
        assert!(derive_encryption_key(&secret, &ctx).is_err());
    }

    #[test]
    fn test_derive_key_rejects_33_byte_secret_fails() {
        let ctx = HybridEncryptionContext::default();
        let secret = vec![0u8; 33];
        assert!(derive_encryption_key(&secret, &ctx).is_err());
    }

    #[test]
    fn test_derive_key_rejects_65_byte_secret_fails() {
        let ctx = HybridEncryptionContext::default();
        let secret = vec![0u8; 65];
        assert!(derive_encryption_key(&secret, &ctx).is_err());
    }

    #[test]
    fn test_derive_key_rejects_empty_secret_fails() {
        let ctx = HybridEncryptionContext::default();
        let secret = vec![];
        assert!(derive_encryption_key(&secret, &ctx).is_err());
    }

    #[test]
    fn test_derive_key_accepts_32_byte_secret_succeeds() {
        let ctx = HybridEncryptionContext::default();
        let secret = vec![0xABu8; 32];
        let result = derive_encryption_key(&secret, &ctx);
        assert!(result.is_ok());
        let key = result.unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_derive_key_accepts_64_byte_secret_succeeds() {
        let ctx = HybridEncryptionContext::default();
        let secret = vec![0xCDu8; 64];
        let result = derive_encryption_key(&secret, &ctx);
        assert!(result.is_ok());
        let key = result.unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_derive_key_deterministic_is_deterministic() {
        let ctx = HybridEncryptionContext::default();
        let secret = vec![42u8; 32];
        let key1 = derive_encryption_key(&secret, &ctx).unwrap();
        let key2 = derive_encryption_key(&secret, &ctx).unwrap();
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_derive_key_different_secrets_produce_different_keys_succeeds() {
        let ctx = HybridEncryptionContext::default();
        let secret_a = vec![1u8; 32];
        let secret_b = vec![2u8; 32];
        let key_a = derive_encryption_key(&secret_a, &ctx).unwrap();
        let key_b = derive_encryption_key(&secret_b, &ctx).unwrap();
        assert_ne!(key_a, key_b);
    }

    #[test]
    fn test_derive_key_different_context_produces_different_key_succeeds() {
        let ctx_a = HybridEncryptionContext { info: b"context-A".to_vec(), aad: vec![] };
        let ctx_b = HybridEncryptionContext { info: b"context-B".to_vec(), aad: vec![] };
        let secret = vec![99u8; 32];
        let key_a = derive_encryption_key(&secret, &ctx_a).unwrap();
        let key_b = derive_encryption_key(&secret, &ctx_b).unwrap();
        assert_ne!(key_a, key_b);
    }

    #[test]
    fn test_derive_key_with_aad_succeeds() {
        let ctx_no_aad = HybridEncryptionContext { info: b"test".to_vec(), aad: vec![] };
        let ctx_with_aad =
            HybridEncryptionContext { info: b"test".to_vec(), aad: b"extra-data".to_vec() };
        let secret = vec![77u8; 32];
        let key_no = derive_encryption_key(&secret, &ctx_no_aad).unwrap();
        let key_with = derive_encryption_key(&secret, &ctx_with_aad).unwrap();
        assert_ne!(key_no, key_with);
    }

    // ============================================================================
    // encrypt() error paths
    // ============================================================================

    #[test]
    fn test_encrypt_rejects_wrong_pk_size_fails() {
        let bad_pk = vec![0u8; 100]; // Wrong size (should be 1184)
        let result = encrypt(&bad_pk, b"hello", None);
        assert!(result.is_err());
        match result.unwrap_err() {
            HybridEncryptionError::InvalidInput(msg) => {
                assert!(msg.contains("1184"));
            }
            other => panic!("Expected InvalidInput, got {:?}", other),
        }
    }

    #[test]
    fn test_encrypt_rejects_empty_pk_fails() {
        let result = encrypt(&[], b"hello", None);
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypt_rejects_oversized_pk_fails() {
        let big_pk = vec![0u8; 2000];
        let result = encrypt(&big_pk, b"hello", None);
        assert!(result.is_err());
    }

    // ============================================================================
    // decrypt() validation error paths
    // ============================================================================

    #[test]
    fn test_decrypt_rejects_wrong_sk_size_fails() {
        let bad_sk = vec![0u8; 100]; // Should be 2400
        let ct = HybridCiphertext::new(
            vec![0u8; 1088],
            vec![],
            vec![0u8; 32],
            vec![0u8; 12],
            vec![0u8; 16],
        );
        let result = decrypt(&bad_sk, &ct, None);
        assert!(result.is_err());
        match result.unwrap_err() {
            HybridEncryptionError::InvalidInput(msg) => {
                assert!(msg.contains("2400"));
            }
            other => panic!("Expected InvalidInput, got {:?}", other),
        }
    }

    #[test]
    fn test_decrypt_rejects_wrong_ct_size_fails() {
        let sk = vec![0u8; 2400];
        let ct = HybridCiphertext::new(
            vec![0u8; 500], // Should be 1088
            vec![],
            vec![0u8; 32],
            vec![0u8; 12],
            vec![0u8; 16],
        );
        let result = decrypt(&sk, &ct, None);
        assert!(result.is_err());
        match result.unwrap_err() {
            HybridEncryptionError::InvalidInput(msg) => {
                assert!(msg.contains("1088"));
            }
            other => panic!("Expected InvalidInput, got {:?}", other),
        }
    }

    #[test]
    fn test_decrypt_rejects_wrong_nonce_size_fails() {
        let sk = vec![0u8; 2400];
        let ct = HybridCiphertext::new(
            vec![0u8; 1088],
            vec![],
            vec![0u8; 32],
            vec![0u8; 8], // Should be 12
            vec![0u8; 16],
        );
        let result = decrypt(&sk, &ct, None);
        assert!(result.is_err());
        match result.unwrap_err() {
            HybridEncryptionError::InvalidInput(msg) => {
                assert!(msg.contains("12"));
            }
            other => panic!("Expected InvalidInput, got {:?}", other),
        }
    }

    #[test]
    fn test_decrypt_rejects_wrong_tag_size_fails() {
        let sk = vec![0u8; 2400];
        let ct = HybridCiphertext::new(
            vec![0u8; 1088],
            vec![],
            vec![0u8; 32],
            vec![0u8; 12],
            vec![0u8; 8], // Should be 16
        );
        let result = decrypt(&sk, &ct, None);
        assert!(result.is_err());
        match result.unwrap_err() {
            HybridEncryptionError::InvalidInput(msg) => {
                assert!(msg.contains("16"));
            }
            other => panic!("Expected InvalidInput, got {:?}", other),
        }
    }

    // ============================================================================
    // decrypt_hybrid() validation error paths
    // ============================================================================

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
        match result.unwrap_err() {
            HybridEncryptionError::InvalidInput(msg) => {
                assert!(msg.contains("1088"));
            }
            other => panic!("Expected InvalidInput, got {:?}", other),
        }
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
        match result.unwrap_err() {
            HybridEncryptionError::InvalidInput(msg) => {
                assert!(msg.contains("32"));
            }
            other => panic!("Expected InvalidInput, got {:?}", other),
        }
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
        match result.unwrap_err() {
            HybridEncryptionError::InvalidInput(msg) => {
                assert!(msg.contains("12"));
            }
            other => panic!("Expected InvalidInput, got {:?}", other),
        }
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
        match result.unwrap_err() {
            HybridEncryptionError::InvalidInput(msg) => {
                assert!(msg.contains("16"));
            }
            other => panic!("Expected InvalidInput, got {:?}", other),
        }
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
        assert_eq!(ctx.info, b"LatticeArc-Hybrid-Encryption-v1");
        assert!(ctx.aad.is_empty());
    }

    #[test]
    fn test_custom_context_succeeds() {
        let ctx =
            HybridEncryptionContext { info: b"custom-info".to_vec(), aad: b"custom-aad".to_vec() };
        assert_eq!(ctx.info, b"custom-info");
        assert_eq!(ctx.aad, b"custom-aad");
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

        let ctx = HybridEncryptionContext {
            info: b"custom-app-v2".to_vec(),
            aad: b"associated-data-123".to_vec(),
        };

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

        let ctx_enc = HybridEncryptionContext { info: b"encrypt-ctx".to_vec(), aad: vec![] };
        let ctx_dec = HybridEncryptionContext { info: b"decrypt-ctx".to_vec(), aad: vec![] };

        let ct = encrypt_hybrid(&pk, plaintext, Some(&ctx_enc)).unwrap();
        let result = decrypt_hybrid(&sk, &ct, Some(&ctx_dec));
        assert!(result.is_err(), "Wrong context should fail");
    }

    // ============================================================================
    // encrypt() / decrypt() error path: encrypt succeeds but decrypt
    // fails due to ML-KEM decapsulation limitation
    // ============================================================================

    #[test]
    fn test_encrypt_none_context_uses_default_succeeds() {
        // Generate a valid ML-KEM public key
        let (pk, _sk) = latticearc::primitives::kem::ml_kem::MlKem::generate_keypair(
            latticearc::primitives::kem::ml_kem::MlKemSecurityLevel::MlKem768,
        )
        .unwrap();

        // Encrypt with None context (uses default)
        let result = encrypt(pk.as_bytes(), b"test", None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_encrypt_with_explicit_context_succeeds() {
        let (pk, _sk) = latticearc::primitives::kem::ml_kem::MlKem::generate_keypair(
            latticearc::primitives::kem::ml_kem::MlKemSecurityLevel::MlKem768,
        )
        .unwrap();

        let ctx = HybridEncryptionContext { info: b"explicit".to_vec(), aad: b"aad-data".to_vec() };
        let result = encrypt(pk.as_bytes(), b"test", Some(&ctx));
        assert!(result.is_ok());
        let ct = result.unwrap();
        assert!(ct.ecdh_ephemeral_pk().is_empty(), "Legacy path has no ECDH PK");
    }

    // ============================================================================
    // Error equality and Debug
    // ============================================================================

    #[test]
    fn test_error_clone_and_eq_fails() {
        let err1 = HybridEncryptionError::KemError("a".to_string());
        let err2 = err1.clone();
        assert_eq!(err1, err2);

        let err3 = HybridEncryptionError::KemError("b".to_string());
        assert_ne!(err1, err3);

        let err4 = HybridEncryptionError::EncryptionError("a".to_string());
        assert_ne!(err1, err4);
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
        assert_eq!(cloned.info, ctx.info);

        let debug = format!("{:?}", ctx);
        assert!(debug.contains("HybridEncryptionContext"));
    }
}

// Originally: hybrid_encrypt_hybrid_validation.rs
mod validation {
    //! Coverage tests for encrypt_hybrid.rs decrypt validation paths
    //! Tests validation errors that don't require actual ML-KEM decapsulation.

    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic)]
    // Legacy `encrypt`/`decrypt` are deprecated; the tests below intentionally exercise
    // them to preserve validation coverage of the legacy ML-KEM-only code path.
    #![allow(deprecated)]

    use latticearc::hybrid::encrypt_hybrid::{
        HybridCiphertext, HybridEncryptionContext, HybridEncryptionError, decrypt, encrypt,
    };

    #[test]
    fn test_decrypt_wrong_ml_kem_sk_length_fails() {
        let ct = HybridCiphertext::new(
            vec![0u8; 1088],
            vec![],
            vec![0u8; 32],
            vec![0u8; 12],
            vec![0u8; 16],
        );
        // SK must be 2400 bytes
        let result = decrypt(&[0u8; 100], &ct, None);
        assert!(result.is_err());
        match result.unwrap_err() {
            HybridEncryptionError::InvalidInput(msg) => {
                assert!(msg.contains("2400"), "Error should mention expected size: {}", msg);
            }
            other => panic!("Expected InvalidInput, got: {:?}", other),
        }
    }

    #[test]
    fn test_decrypt_wrong_kem_ciphertext_length_fails() {
        let ct = HybridCiphertext::new(
            vec![0u8; 500],
            vec![],
            vec![0u8; 32],
            vec![0u8; 12],
            vec![0u8; 16],
        ); // Wrong: should be 1088
        let result = decrypt(&[0u8; 2400], &ct, None);
        assert!(result.is_err());
        match result.unwrap_err() {
            HybridEncryptionError::InvalidInput(msg) => {
                assert!(msg.contains("1088"), "Error should mention expected size: {}", msg);
            }
            other => panic!("Expected InvalidInput, got: {:?}", other),
        }
    }

    #[test]
    fn test_decrypt_wrong_nonce_length_fails() {
        let ct = HybridCiphertext::new(
            vec![0u8; 1088],
            vec![],
            vec![0u8; 32],
            vec![0u8; 8],
            vec![0u8; 16],
        ); // Wrong: nonce should be 12
        let result = decrypt(&[0u8; 2400], &ct, None);
        assert!(result.is_err());
        match result.unwrap_err() {
            HybridEncryptionError::InvalidInput(msg) => {
                assert!(msg.contains("12"), "Error should mention expected nonce size: {}", msg);
            }
            other => panic!("Expected InvalidInput, got: {:?}", other),
        }
    }

    #[test]
    fn test_decrypt_wrong_tag_length_fails() {
        let ct = HybridCiphertext::new(
            vec![0u8; 1088],
            vec![],
            vec![0u8; 32],
            vec![0u8; 12],
            vec![0u8; 8],
        ); // Wrong: tag should be 16
        let result = decrypt(&[0u8; 2400], &ct, None);
        assert!(result.is_err());
        match result.unwrap_err() {
            HybridEncryptionError::InvalidInput(msg) => {
                assert!(msg.contains("16"), "Error should mention expected tag size: {}", msg);
            }
            other => panic!("Expected InvalidInput, got: {:?}", other),
        }
    }

    #[test]
    fn test_encrypt_invalid_pk_length_fails() {
        let result = encrypt(&[0u8; 100], b"test", None);
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypt_with_context_succeeds() {
        use latticearc::primitives::kem::ml_kem::{MlKem, MlKemSecurityLevel};
        let (pk, _sk) = MlKem::generate_keypair(MlKemSecurityLevel::MlKem768).unwrap();

        let context =
            HybridEncryptionContext { info: b"test-info".to_vec(), aad: b"test-aad".to_vec() };

        let result = encrypt(pk.as_bytes(), b"secret data", Some(&context));
        assert!(result.is_ok(), "Encrypt with context should succeed");
        let ct = result.unwrap();
        assert_eq!(ct.kem_ciphertext().len(), 1088);
        assert_eq!(ct.nonce().len(), 12);
        assert_eq!(ct.tag().len(), 16);
        assert!(!ct.symmetric_ciphertext().is_empty());
    }

    #[test]
    fn test_encrypt_default_context_succeeds() {
        use latticearc::primitives::kem::ml_kem::{MlKem, MlKemSecurityLevel};
        let (pk, _sk) = MlKem::generate_keypair(MlKemSecurityLevel::MlKem768).unwrap();

        // None context uses default
        let result = encrypt(pk.as_bytes(), b"test data", None);
        assert!(result.is_ok(), "Encrypt with None context should succeed");
    }

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
        let ctx = HybridEncryptionContext { info: b"info".to_vec(), aad: b"aad".to_vec() };
        let cloned = ctx.clone();
        assert_eq!(cloned.info, ctx.info);
        let debug = format!("{:?}", ctx);
        assert!(debug.contains("HybridEncryptionContext"));

        let default = HybridEncryptionContext::default();
        assert!(!default.info.is_empty());
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

        // Clone and PartialEq
        assert_eq!(e1.clone(), e1);
        assert_ne!(e1, e2);
    }

    #[test]
    fn test_decrypt_with_wrong_sk_bytes_valid_length_fails() {
        // Valid lengths but garbage bytes — should fail at ML-KEM decapsulation
        let ct = HybridCiphertext::new(
            vec![0xAA; 1088],
            vec![],
            vec![0xBB; 32],
            vec![0xCC; 12],
            vec![0xDD; 16],
        );

        // Valid length (2400) but wrong key material
        let fake_sk = vec![0xFF; 2400];
        let result = decrypt(&fake_sk, &ct, None);
        // This should fail at ML-KEM decapsulation or AES-GCM auth
        assert!(result.is_err());
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
    // Legacy `encrypt`/`decrypt` are deprecated; the tests below intentionally exercise
    // them to preserve coverage of the legacy ML-KEM-only code path.
    #![allow(deprecated)]

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
        let ctx = HybridEncryptionContext {
            info: b"LatticeArc-Test-v1".to_vec(),
            aad: b"additional-auth-data".to_vec(),
        };

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

        let ctx1 = HybridEncryptionContext {
            info: b"LatticeArc-Test-v1".to_vec(),
            aad: b"correct-aad".to_vec(),
        };
        let ctx2 = HybridEncryptionContext {
            info: b"LatticeArc-Test-v1".to_vec(),
            aad: b"wrong-aad".to_vec(),
        };

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

    // ============================================================
    // Legacy decrypt() error paths (ML-KEM only)
    // ============================================================

    #[test]
    fn test_legacy_decrypt_bad_sk_length_fails() {
        use latticearc::hybrid::encrypt_hybrid::decrypt;

        let bad_ct = HybridCiphertext::new(
            vec![0u8; 1088],
            vec![],
            vec![0u8; 16],
            vec![0u8; 12],
            vec![0u8; 16],
        );
        let bad_sk = vec![0u8; 100]; // wrong length, expect 2400
        let result = decrypt(&bad_sk, &bad_ct, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_legacy_decrypt_bad_kem_ct_length_fails() {
        use latticearc::hybrid::encrypt_hybrid::decrypt;

        let bad_ct = HybridCiphertext::new(
            vec![0u8; 100], // wrong length, expect 1088
            vec![],
            vec![0u8; 16],
            vec![0u8; 12],
            vec![0u8; 16],
        );
        let sk = vec![0u8; 2400];
        let result = decrypt(&sk, &bad_ct, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_legacy_decrypt_bad_nonce_length_fails() {
        use latticearc::hybrid::encrypt_hybrid::decrypt;

        let bad_ct = HybridCiphertext::new(
            vec![0u8; 1088],
            vec![],
            vec![0u8; 16],
            vec![0u8; 5], // wrong length, expect 12
            vec![0u8; 16],
        );
        let sk = vec![0u8; 2400];
        let result = decrypt(&sk, &bad_ct, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_legacy_decrypt_bad_tag_length_fails() {
        use latticearc::hybrid::encrypt_hybrid::decrypt;

        let bad_ct = HybridCiphertext::new(
            vec![0u8; 1088],
            vec![],
            vec![0u8; 16],
            vec![0u8; 12],
            vec![0u8; 5], // wrong length, expect 16
        );
        let sk = vec![0u8; 2400];
        let result = decrypt(&sk, &bad_ct, None);
        assert!(result.is_err());
    }

    // ============================================================
    // Legacy encrypt() with valid pk (ML-KEM only path)
    // ============================================================

    #[test]
    fn test_legacy_encrypt_success_succeeds() {
        use latticearc::hybrid::encrypt_hybrid::encrypt;
        use latticearc::primitives::kem::ml_kem::{MlKem, MlKemSecurityLevel};

        let (ml_kem_pk, _sk) = MlKem::generate_keypair(MlKemSecurityLevel::MlKem768).unwrap();

        let plaintext = b"Legacy ML-KEM-only encrypt test";
        let ct = encrypt(ml_kem_pk.as_bytes(), plaintext, None);
        assert!(ct.is_ok(), "Legacy encrypt should succeed with valid ML-KEM pk");
        let ct = ct.unwrap();
        assert_eq!(ct.kem_ciphertext().len(), 1088);
        assert_eq!(ct.nonce().len(), 12);
        assert_eq!(ct.tag().len(), 16);
    }

    #[test]
    fn test_legacy_encrypt_bad_pk_length_fails() {
        use latticearc::hybrid::encrypt_hybrid::encrypt;

        let bad_pk = vec![0u8; 100]; // wrong length, expect 1184
        let result = encrypt(&bad_pk, b"test", None);
        assert!(result.is_err());
    }
}
