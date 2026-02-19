#![deny(unsafe_code)]
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
    HybridCiphertext, HybridEncryptionContext, HybridEncryptionError, decrypt, decrypt_hybrid,
    derive_encryption_key, encrypt, encrypt_hybrid,
};
use latticearc::hybrid::kem_hybrid::generate_keypair;
use rand::rngs::OsRng;

// ============================================================================
// derive_encryption_key error paths
// ============================================================================

#[test]
fn test_derive_key_rejects_too_short_secret() {
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
fn test_derive_key_rejects_31_byte_secret() {
    let ctx = HybridEncryptionContext::default();
    let secret = vec![0u8; 31];
    assert!(derive_encryption_key(&secret, &ctx).is_err());
}

#[test]
fn test_derive_key_rejects_33_byte_secret() {
    let ctx = HybridEncryptionContext::default();
    let secret = vec![0u8; 33];
    assert!(derive_encryption_key(&secret, &ctx).is_err());
}

#[test]
fn test_derive_key_rejects_65_byte_secret() {
    let ctx = HybridEncryptionContext::default();
    let secret = vec![0u8; 65];
    assert!(derive_encryption_key(&secret, &ctx).is_err());
}

#[test]
fn test_derive_key_rejects_empty_secret() {
    let ctx = HybridEncryptionContext::default();
    let secret = vec![];
    assert!(derive_encryption_key(&secret, &ctx).is_err());
}

#[test]
fn test_derive_key_accepts_32_byte_secret() {
    let ctx = HybridEncryptionContext::default();
    let secret = vec![0xABu8; 32];
    let result = derive_encryption_key(&secret, &ctx);
    assert!(result.is_ok());
    let key = result.unwrap();
    assert_eq!(key.len(), 32);
}

#[test]
fn test_derive_key_accepts_64_byte_secret() {
    let ctx = HybridEncryptionContext::default();
    let secret = vec![0xCDu8; 64];
    let result = derive_encryption_key(&secret, &ctx);
    assert!(result.is_ok());
    let key = result.unwrap();
    assert_eq!(key.len(), 32);
}

#[test]
fn test_derive_key_deterministic() {
    let ctx = HybridEncryptionContext::default();
    let secret = vec![42u8; 32];
    let key1 = derive_encryption_key(&secret, &ctx).unwrap();
    let key2 = derive_encryption_key(&secret, &ctx).unwrap();
    assert_eq!(key1, key2);
}

#[test]
fn test_derive_key_different_secrets_produce_different_keys() {
    let ctx = HybridEncryptionContext::default();
    let secret_a = vec![1u8; 32];
    let secret_b = vec![2u8; 32];
    let key_a = derive_encryption_key(&secret_a, &ctx).unwrap();
    let key_b = derive_encryption_key(&secret_b, &ctx).unwrap();
    assert_ne!(key_a, key_b);
}

#[test]
fn test_derive_key_different_context_produces_different_key() {
    let ctx_a = HybridEncryptionContext { info: b"context-A".to_vec(), aad: vec![] };
    let ctx_b = HybridEncryptionContext { info: b"context-B".to_vec(), aad: vec![] };
    let secret = vec![99u8; 32];
    let key_a = derive_encryption_key(&secret, &ctx_a).unwrap();
    let key_b = derive_encryption_key(&secret, &ctx_b).unwrap();
    assert_ne!(key_a, key_b);
}

#[test]
fn test_derive_key_with_aad() {
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
fn test_encrypt_rejects_wrong_pk_size() {
    let mut rng = OsRng;
    let bad_pk = vec![0u8; 100]; // Wrong size (should be 1184)
    let result = encrypt(&mut rng, &bad_pk, b"hello", None);
    assert!(result.is_err());
    match result.unwrap_err() {
        HybridEncryptionError::InvalidInput(msg) => {
            assert!(msg.contains("1184"));
        }
        other => panic!("Expected InvalidInput, got {:?}", other),
    }
}

#[test]
fn test_encrypt_rejects_empty_pk() {
    let mut rng = OsRng;
    let result = encrypt(&mut rng, &[], b"hello", None);
    assert!(result.is_err());
}

#[test]
fn test_encrypt_rejects_oversized_pk() {
    let mut rng = OsRng;
    let big_pk = vec![0u8; 2000];
    let result = encrypt(&mut rng, &big_pk, b"hello", None);
    assert!(result.is_err());
}

// ============================================================================
// decrypt() validation error paths
// ============================================================================

#[test]
fn test_decrypt_rejects_wrong_sk_size() {
    let bad_sk = vec![0u8; 100]; // Should be 2400
    let ct = HybridCiphertext {
        kem_ciphertext: vec![0u8; 1088],
        ecdh_ephemeral_pk: vec![],
        symmetric_ciphertext: vec![0u8; 32],
        nonce: vec![0u8; 12],
        tag: vec![0u8; 16],
    };
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
fn test_decrypt_rejects_wrong_ct_size() {
    let sk = vec![0u8; 2400];
    let ct = HybridCiphertext {
        kem_ciphertext: vec![0u8; 500], // Should be 1088
        ecdh_ephemeral_pk: vec![],
        symmetric_ciphertext: vec![0u8; 32],
        nonce: vec![0u8; 12],
        tag: vec![0u8; 16],
    };
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
fn test_decrypt_rejects_wrong_nonce_size() {
    let sk = vec![0u8; 2400];
    let ct = HybridCiphertext {
        kem_ciphertext: vec![0u8; 1088],
        ecdh_ephemeral_pk: vec![],
        symmetric_ciphertext: vec![0u8; 32],
        nonce: vec![0u8; 8], // Should be 12
        tag: vec![0u8; 16],
    };
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
fn test_decrypt_rejects_wrong_tag_size() {
    let sk = vec![0u8; 2400];
    let ct = HybridCiphertext {
        kem_ciphertext: vec![0u8; 1088],
        ecdh_ephemeral_pk: vec![],
        symmetric_ciphertext: vec![0u8; 32],
        nonce: vec![0u8; 12],
        tag: vec![0u8; 8], // Should be 16
    };
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
fn test_decrypt_hybrid_rejects_wrong_kem_ct_size() {
    let mut rng = OsRng;
    let (_pk, sk) = generate_keypair(&mut rng).unwrap();
    let ct = HybridCiphertext {
        kem_ciphertext: vec![0u8; 500], // Should be 1088
        ecdh_ephemeral_pk: vec![0u8; 32],
        symmetric_ciphertext: vec![0u8; 32],
        nonce: vec![0u8; 12],
        tag: vec![0u8; 16],
    };
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
fn test_decrypt_hybrid_rejects_wrong_ecdh_pk_size() {
    let mut rng = OsRng;
    let (_pk, sk) = generate_keypair(&mut rng).unwrap();
    let ct = HybridCiphertext {
        kem_ciphertext: vec![0u8; 1088],
        ecdh_ephemeral_pk: vec![0u8; 16], // Should be 32
        symmetric_ciphertext: vec![0u8; 32],
        nonce: vec![0u8; 12],
        tag: vec![0u8; 16],
    };
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
fn test_decrypt_hybrid_rejects_wrong_nonce_size() {
    let mut rng = OsRng;
    let (_pk, sk) = generate_keypair(&mut rng).unwrap();
    let ct = HybridCiphertext {
        kem_ciphertext: vec![0u8; 1088],
        ecdh_ephemeral_pk: vec![0u8; 32],
        symmetric_ciphertext: vec![0u8; 32],
        nonce: vec![0u8; 8], // Should be 12
        tag: vec![0u8; 16],
    };
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
fn test_decrypt_hybrid_rejects_wrong_tag_size() {
    let mut rng = OsRng;
    let (_pk, sk) = generate_keypair(&mut rng).unwrap();
    let ct = HybridCiphertext {
        kem_ciphertext: vec![0u8; 1088],
        ecdh_ephemeral_pk: vec![0u8; 32],
        symmetric_ciphertext: vec![0u8; 32],
        nonce: vec![0u8; 12],
        tag: vec![0u8; 4], // Should be 16
    };
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
fn test_error_display_kem_error() {
    let err = HybridEncryptionError::KemError("test kem".to_string());
    let msg = format!("{}", err);
    assert!(msg.contains("KEM error"));
    assert!(msg.contains("test kem"));
}

#[test]
fn test_error_display_encryption_error() {
    let err = HybridEncryptionError::EncryptionError("test enc".to_string());
    let msg = format!("{}", err);
    assert!(msg.contains("Encryption error"));
}

#[test]
fn test_error_display_decryption_error() {
    let err = HybridEncryptionError::DecryptionError("test dec".to_string());
    let msg = format!("{}", err);
    assert!(msg.contains("Decryption error"));
}

#[test]
fn test_error_display_kdf_error() {
    let err = HybridEncryptionError::KdfError("test kdf".to_string());
    let msg = format!("{}", err);
    assert!(msg.contains("Key derivation error"));
}

#[test]
fn test_error_display_invalid_input() {
    let err = HybridEncryptionError::InvalidInput("test input".to_string());
    let msg = format!("{}", err);
    assert!(msg.contains("Invalid input"));
}

#[test]
fn test_error_display_key_length_error() {
    let err = HybridEncryptionError::KeyLengthError { expected: 32, actual: 16 };
    let msg = format!("{}", err);
    assert!(msg.contains("32"));
    assert!(msg.contains("16"));
}

// ============================================================================
// HybridEncryptionContext coverage
// ============================================================================

#[test]
fn test_default_context() {
    let ctx = HybridEncryptionContext::default();
    assert_eq!(ctx.info, b"LatticeArc-Hybrid-Encryption-v1");
    assert!(ctx.aad.is_empty());
}

#[test]
fn test_custom_context() {
    let ctx =
        HybridEncryptionContext { info: b"custom-info".to_vec(), aad: b"custom-aad".to_vec() };
    assert_eq!(ctx.info, b"custom-info");
    assert_eq!(ctx.aad, b"custom-aad");
}

// ============================================================================
// HybridCiphertext coverage
// ============================================================================

#[test]
fn test_ciphertext_clone_and_debug() {
    let ct = HybridCiphertext {
        kem_ciphertext: vec![1, 2, 3],
        ecdh_ephemeral_pk: vec![4, 5],
        symmetric_ciphertext: vec![6, 7, 8],
        nonce: vec![9, 10],
        tag: vec![11, 12],
    };
    let cloned = ct.clone();
    assert_eq!(cloned.kem_ciphertext, ct.kem_ciphertext);
    assert_eq!(cloned.ecdh_ephemeral_pk, ct.ecdh_ephemeral_pk);
    assert_eq!(cloned.symmetric_ciphertext, ct.symmetric_ciphertext);
    assert_eq!(cloned.nonce, ct.nonce);
    assert_eq!(cloned.tag, ct.tag);

    let debug = format!("{:?}", ct);
    assert!(debug.contains("HybridCiphertext"));
}

// ============================================================================
// encrypt_hybrid / decrypt_hybrid with custom context
// ============================================================================

#[test]
fn test_encrypt_decrypt_hybrid_with_custom_context() {
    let mut rng = OsRng;
    let (pk, sk) = generate_keypair(&mut rng).unwrap();
    let plaintext = b"test with custom context and AAD";

    let ctx = HybridEncryptionContext {
        info: b"custom-app-v2".to_vec(),
        aad: b"associated-data-123".to_vec(),
    };

    let ct = encrypt_hybrid(&mut rng, &pk, plaintext, Some(&ctx)).unwrap();
    assert!(!ct.symmetric_ciphertext.is_empty());
    assert_eq!(ct.nonce.len(), 12);
    assert_eq!(ct.tag.len(), 16);
    assert_eq!(ct.ecdh_ephemeral_pk.len(), 32);
    assert_eq!(ct.kem_ciphertext.len(), 1088);

    let decrypted = decrypt_hybrid(&sk, &ct, Some(&ctx)).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_encrypt_decrypt_hybrid_without_context() {
    let mut rng = OsRng;
    let (pk, sk) = generate_keypair(&mut rng).unwrap();
    let plaintext = b"no context provided";

    let ct = encrypt_hybrid(&mut rng, &pk, plaintext, None).unwrap();
    let decrypted = decrypt_hybrid(&sk, &ct, None).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_encrypt_hybrid_empty_plaintext() {
    let mut rng = OsRng;
    let (pk, sk) = generate_keypair(&mut rng).unwrap();
    let plaintext = b"";

    let ct = encrypt_hybrid(&mut rng, &pk, plaintext, None).unwrap();
    let decrypted = decrypt_hybrid(&sk, &ct, None).unwrap();
    assert_eq!(decrypted, plaintext.to_vec());
}

#[test]
fn test_encrypt_hybrid_large_plaintext() {
    let mut rng = OsRng;
    let (pk, sk) = generate_keypair(&mut rng).unwrap();
    let plaintext = vec![0xAAu8; 65536]; // 64KB

    let ct = encrypt_hybrid(&mut rng, &pk, &plaintext, None).unwrap();
    let decrypted = decrypt_hybrid(&sk, &ct, None).unwrap();
    assert_eq!(decrypted, plaintext);
}

// ============================================================================
// Tamper detection for hybrid path
// ============================================================================

#[test]
fn test_decrypt_hybrid_tampered_ciphertext() {
    let mut rng = OsRng;
    let (pk, sk) = generate_keypair(&mut rng).unwrap();
    let plaintext = b"tamper test";

    let mut ct = encrypt_hybrid(&mut rng, &pk, plaintext, None).unwrap();
    // Flip a byte in symmetric ciphertext
    if let Some(byte) = ct.symmetric_ciphertext.first_mut() {
        *byte ^= 0xFF;
    }

    let result = decrypt_hybrid(&sk, &ct, None);
    assert!(result.is_err(), "Tampered ciphertext should fail decryption");
}

#[test]
fn test_decrypt_hybrid_wrong_context() {
    let mut rng = OsRng;
    let (pk, sk) = generate_keypair(&mut rng).unwrap();
    let plaintext = b"context mismatch test";

    let ctx_enc = HybridEncryptionContext { info: b"encrypt-ctx".to_vec(), aad: vec![] };
    let ctx_dec = HybridEncryptionContext { info: b"decrypt-ctx".to_vec(), aad: vec![] };

    let ct = encrypt_hybrid(&mut rng, &pk, plaintext, Some(&ctx_enc)).unwrap();
    let result = decrypt_hybrid(&sk, &ct, Some(&ctx_dec));
    assert!(result.is_err(), "Wrong context should fail");
}

// ============================================================================
// encrypt() / decrypt() error path: encrypt succeeds but decrypt
// fails due to ML-KEM decapsulation limitation
// ============================================================================

#[test]
fn test_encrypt_none_context_uses_default() {
    let mut rng = OsRng;
    // Generate a valid ML-KEM public key
    let (pk, _sk) = latticearc::primitives::kem::ml_kem::MlKem::generate_keypair(
        &mut rng,
        latticearc::primitives::kem::ml_kem::MlKemSecurityLevel::MlKem768,
    )
    .unwrap();

    // Encrypt with None context (uses default)
    let result = encrypt(&mut rng, pk.as_bytes(), b"test", None);
    assert!(result.is_ok());
}

#[test]
fn test_encrypt_with_explicit_context() {
    let mut rng = OsRng;
    let (pk, _sk) = latticearc::primitives::kem::ml_kem::MlKem::generate_keypair(
        &mut rng,
        latticearc::primitives::kem::ml_kem::MlKemSecurityLevel::MlKem768,
    )
    .unwrap();

    let ctx = HybridEncryptionContext { info: b"explicit".to_vec(), aad: b"aad-data".to_vec() };
    let result = encrypt(&mut rng, pk.as_bytes(), b"test", Some(&ctx));
    assert!(result.is_ok());
    let ct = result.unwrap();
    assert!(ct.ecdh_ephemeral_pk.is_empty(), "Legacy path has no ECDH PK");
}

// ============================================================================
// Error equality and Debug
// ============================================================================

#[test]
fn test_error_clone_and_eq() {
    let err1 = HybridEncryptionError::KemError("a".to_string());
    let err2 = err1.clone();
    assert_eq!(err1, err2);

    let err3 = HybridEncryptionError::KemError("b".to_string());
    assert_ne!(err1, err3);

    let err4 = HybridEncryptionError::EncryptionError("a".to_string());
    assert_ne!(err1, err4);
}

#[test]
fn test_error_debug() {
    let err = HybridEncryptionError::KeyLengthError { expected: 32, actual: 0 };
    let debug = format!("{:?}", err);
    assert!(debug.contains("KeyLengthError"));
}

#[test]
fn test_context_clone_and_debug() {
    let ctx = HybridEncryptionContext::default();
    let cloned = ctx.clone();
    assert_eq!(cloned.info, ctx.info);

    let debug = format!("{:?}", ctx);
    assert!(debug.contains("HybridEncryptionContext"));
}
