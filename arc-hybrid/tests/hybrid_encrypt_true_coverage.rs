//! Coverage tests for encrypt_hybrid.rs — true hybrid (ML-KEM + X25519)
//! encrypt/decrypt roundtrip and error paths.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::cast_precision_loss,
    deprecated
)]

use arc_hybrid::encrypt_hybrid::{
    HybridCiphertext, HybridEncryptionContext, decrypt_hybrid, encrypt_hybrid,
};
use arc_hybrid::kem_hybrid;

// ============================================================
// True hybrid encrypt/decrypt roundtrip
// ============================================================

#[test]
fn test_true_hybrid_encrypt_decrypt_roundtrip() {
    let mut rng = rand::thread_rng();
    let (hybrid_pk, hybrid_sk) = kem_hybrid::generate_keypair(&mut rng).unwrap();

    let plaintext = b"True hybrid encryption roundtrip test";
    let ct = encrypt_hybrid(&mut rng, &hybrid_pk, plaintext, None).unwrap();

    assert_eq!(ct.kem_ciphertext.len(), 1088, "ML-KEM-768 ciphertext");
    assert_eq!(ct.ecdh_ephemeral_pk.len(), 32, "X25519 ephemeral pk");
    assert_eq!(ct.nonce.len(), 12, "AES-GCM nonce");
    assert_eq!(ct.tag.len(), 16, "AES-GCM tag");
    assert!(!ct.symmetric_ciphertext.is_empty());

    let decrypted = decrypt_hybrid(&hybrid_sk, &ct, None).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_true_hybrid_encrypt_decrypt_with_context() {
    let mut rng = rand::thread_rng();
    let (hybrid_pk, hybrid_sk) = kem_hybrid::generate_keypair(&mut rng).unwrap();

    let plaintext = b"True hybrid with custom context";
    let ctx = HybridEncryptionContext {
        info: b"LatticeArc-Test-v1".to_vec(),
        aad: b"additional-auth-data".to_vec(),
    };

    let ct = encrypt_hybrid(&mut rng, &hybrid_pk, plaintext, Some(&ctx)).unwrap();
    let decrypted = decrypt_hybrid(&hybrid_sk, &ct, Some(&ctx)).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_true_hybrid_encrypt_empty_plaintext() {
    let mut rng = rand::thread_rng();
    let (hybrid_pk, hybrid_sk) = kem_hybrid::generate_keypair(&mut rng).unwrap();

    let plaintext = b"";
    let ct = encrypt_hybrid(&mut rng, &hybrid_pk, plaintext, None).unwrap();
    let decrypted = decrypt_hybrid(&hybrid_sk, &ct, None).unwrap();
    assert!(decrypted.is_empty());
}

#[test]
fn test_true_hybrid_decrypt_wrong_aad_fails() {
    let mut rng = rand::thread_rng();
    let (hybrid_pk, hybrid_sk) = kem_hybrid::generate_keypair(&mut rng).unwrap();

    let ctx1 = HybridEncryptionContext {
        info: b"LatticeArc-Test-v1".to_vec(),
        aad: b"correct-aad".to_vec(),
    };
    let ctx2 = HybridEncryptionContext {
        info: b"LatticeArc-Test-v1".to_vec(),
        aad: b"wrong-aad".to_vec(),
    };

    let plaintext = b"AAD mismatch test";
    let ct = encrypt_hybrid(&mut rng, &hybrid_pk, plaintext, Some(&ctx1)).unwrap();
    let result = decrypt_hybrid(&hybrid_sk, &ct, Some(&ctx2));
    assert!(result.is_err(), "Decryption with wrong AAD should fail");
}

// ============================================================
// decrypt_hybrid error paths (bad ciphertext structure)
// ============================================================

#[test]
fn test_decrypt_hybrid_bad_kem_ciphertext_length() {
    let mut rng = rand::thread_rng();
    let (_hybrid_pk, hybrid_sk) = kem_hybrid::generate_keypair(&mut rng).unwrap();

    let bad_ct = HybridCiphertext {
        kem_ciphertext: vec![0u8; 100], // wrong length, expect 1088
        ecdh_ephemeral_pk: vec![0u8; 32],
        symmetric_ciphertext: vec![0u8; 16],
        nonce: vec![0u8; 12],
        tag: vec![0u8; 16],
    };
    let result = decrypt_hybrid(&hybrid_sk, &bad_ct, None);
    assert!(result.is_err());
}

#[test]
fn test_decrypt_hybrid_bad_ecdh_pk_length() {
    let mut rng = rand::thread_rng();
    let (_hybrid_pk, hybrid_sk) = kem_hybrid::generate_keypair(&mut rng).unwrap();

    let bad_ct = HybridCiphertext {
        kem_ciphertext: vec![0u8; 1088],
        ecdh_ephemeral_pk: vec![0u8; 10], // wrong length, expect 32
        symmetric_ciphertext: vec![0u8; 16],
        nonce: vec![0u8; 12],
        tag: vec![0u8; 16],
    };
    let result = decrypt_hybrid(&hybrid_sk, &bad_ct, None);
    assert!(result.is_err());
}

#[test]
fn test_decrypt_hybrid_bad_nonce_length() {
    let mut rng = rand::thread_rng();
    let (_hybrid_pk, hybrid_sk) = kem_hybrid::generate_keypair(&mut rng).unwrap();

    let bad_ct = HybridCiphertext {
        kem_ciphertext: vec![0u8; 1088],
        ecdh_ephemeral_pk: vec![0u8; 32],
        symmetric_ciphertext: vec![0u8; 16],
        nonce: vec![0u8; 5], // wrong length, expect 12
        tag: vec![0u8; 16],
    };
    let result = decrypt_hybrid(&hybrid_sk, &bad_ct, None);
    assert!(result.is_err());
}

#[test]
fn test_decrypt_hybrid_bad_tag_length() {
    let mut rng = rand::thread_rng();
    let (_hybrid_pk, hybrid_sk) = kem_hybrid::generate_keypair(&mut rng).unwrap();

    let bad_ct = HybridCiphertext {
        kem_ciphertext: vec![0u8; 1088],
        ecdh_ephemeral_pk: vec![0u8; 32],
        symmetric_ciphertext: vec![0u8; 16],
        nonce: vec![0u8; 12],
        tag: vec![0u8; 5], // wrong length, expect 16
    };
    let result = decrypt_hybrid(&hybrid_sk, &bad_ct, None);
    assert!(result.is_err());
}

// ============================================================
// Legacy decrypt() error paths (ML-KEM only)
// ============================================================

#[test]
fn test_legacy_decrypt_bad_sk_length() {
    use arc_hybrid::encrypt_hybrid::decrypt;

    let bad_ct = HybridCiphertext {
        kem_ciphertext: vec![0u8; 1088],
        ecdh_ephemeral_pk: vec![],
        symmetric_ciphertext: vec![0u8; 16],
        nonce: vec![0u8; 12],
        tag: vec![0u8; 16],
    };
    let bad_sk = vec![0u8; 100]; // wrong length, expect 2400
    let result = decrypt(&bad_sk, &bad_ct, None);
    assert!(result.is_err());
}

#[test]
fn test_legacy_decrypt_bad_kem_ct_length() {
    use arc_hybrid::encrypt_hybrid::decrypt;

    let bad_ct = HybridCiphertext {
        kem_ciphertext: vec![0u8; 100], // wrong length, expect 1088
        ecdh_ephemeral_pk: vec![],
        symmetric_ciphertext: vec![0u8; 16],
        nonce: vec![0u8; 12],
        tag: vec![0u8; 16],
    };
    let sk = vec![0u8; 2400];
    let result = decrypt(&sk, &bad_ct, None);
    assert!(result.is_err());
}

#[test]
fn test_legacy_decrypt_bad_nonce_length() {
    use arc_hybrid::encrypt_hybrid::decrypt;

    let bad_ct = HybridCiphertext {
        kem_ciphertext: vec![0u8; 1088],
        ecdh_ephemeral_pk: vec![],
        symmetric_ciphertext: vec![0u8; 16],
        nonce: vec![0u8; 5], // wrong length, expect 12
        tag: vec![0u8; 16],
    };
    let sk = vec![0u8; 2400];
    let result = decrypt(&sk, &bad_ct, None);
    assert!(result.is_err());
}

#[test]
fn test_legacy_decrypt_bad_tag_length() {
    use arc_hybrid::encrypt_hybrid::decrypt;

    let bad_ct = HybridCiphertext {
        kem_ciphertext: vec![0u8; 1088],
        ecdh_ephemeral_pk: vec![],
        symmetric_ciphertext: vec![0u8; 16],
        nonce: vec![0u8; 12],
        tag: vec![0u8; 5], // wrong length, expect 16
    };
    let sk = vec![0u8; 2400];
    let result = decrypt(&sk, &bad_ct, None);
    assert!(result.is_err());
}

// ============================================================
// Legacy encrypt() with valid pk (ML-KEM only path)
// ============================================================

#[test]
fn test_legacy_encrypt_success() {
    use arc_hybrid::encrypt_hybrid::encrypt;
    use arc_primitives::kem::ml_kem::{MlKem, MlKemSecurityLevel};

    let mut rng = rand::thread_rng();
    let (ml_kem_pk, _sk) = MlKem::generate_keypair(&mut rng, MlKemSecurityLevel::MlKem768).unwrap();

    let plaintext = b"Legacy ML-KEM-only encrypt test";
    let ct = encrypt(&mut rng, ml_kem_pk.as_bytes(), plaintext, None);
    assert!(ct.is_ok(), "Legacy encrypt should succeed with valid ML-KEM pk");
    let ct = ct.unwrap();
    assert_eq!(ct.kem_ciphertext.len(), 1088);
    assert_eq!(ct.nonce.len(), 12);
    assert_eq!(ct.tag.len(), 16);
}

#[test]
fn test_legacy_encrypt_bad_pk_length() {
    use arc_hybrid::encrypt_hybrid::encrypt;

    let mut rng = rand::thread_rng();
    let bad_pk = vec![0u8; 100]; // wrong length, expect 1184
    let result = encrypt(&mut rng, &bad_pk, b"test", None);
    assert!(result.is_err());
}
