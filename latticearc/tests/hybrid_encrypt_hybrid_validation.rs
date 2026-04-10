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
    let ct =
        HybridCiphertext::new(vec![0u8; 1088], vec![], vec![0u8; 32], vec![0u8; 12], vec![0u8; 16]);
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
    let ct =
        HybridCiphertext::new(vec![0u8; 500], vec![], vec![0u8; 32], vec![0u8; 12], vec![0u8; 16]); // Wrong: should be 1088
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
    let ct =
        HybridCiphertext::new(vec![0u8; 1088], vec![], vec![0u8; 32], vec![0u8; 8], vec![0u8; 16]); // Wrong: nonce should be 12
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
    let ct =
        HybridCiphertext::new(vec![0u8; 1088], vec![], vec![0u8; 32], vec![0u8; 12], vec![0u8; 8]); // Wrong: tag should be 16
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
    let ct =
        HybridCiphertext::new(vec![1, 2, 3], vec![4, 5], vec![6, 7, 8], vec![9, 10], vec![11, 12]);
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
