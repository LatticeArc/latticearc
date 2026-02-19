#![deny(unsafe_code)]
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

use latticearc::hybrid::encrypt_hybrid::{HybridEncryptionContext, decrypt_hybrid, encrypt_hybrid};
use latticearc::hybrid::kem_hybrid::{decapsulate, encapsulate, generate_keypair};
use latticearc::hybrid::sig_hybrid::{self as sig};
use rand::rngs::OsRng;

// ============================================================================
// KEM Roundtrip Tests
// ============================================================================

#[test]
fn test_kem_generate_encapsulate_decapsulate() {
    let mut rng = OsRng;
    let (pk, sk) = generate_keypair(&mut rng).expect("keygen should succeed");

    let enc_key = encapsulate(&mut rng, &pk).expect("encap should succeed");
    let dec_secret = decapsulate(&sk, &enc_key).expect("decap should succeed");

    assert_eq!(
        dec_secret.as_slice(),
        enc_key.shared_secret.as_slice(),
        "Encapsulated and decapsulated secrets must match"
    );
    assert_eq!(dec_secret.len(), 64, "Hybrid shared secret should be 64 bytes");
}

#[test]
fn test_kem_multiple_encapsulations_same_key() {
    let mut rng = OsRng;
    let (pk, sk) = generate_keypair(&mut rng).expect("keygen should succeed");

    for i in 0..10u32 {
        let enc_key =
            encapsulate(&mut rng, &pk).unwrap_or_else(|e| panic!("encap {} failed: {:?}", i, e));
        let dec_secret =
            decapsulate(&sk, &enc_key).unwrap_or_else(|e| panic!("decap {} failed: {:?}", i, e));

        assert_eq!(
            dec_secret.as_slice(),
            enc_key.shared_secret.as_slice(),
            "Roundtrip {} secret mismatch",
            i
        );
    }
}

#[test]
fn test_kem_different_keypairs_different_secrets() {
    let mut rng = OsRng;
    let (pk_a, _sk_a) = generate_keypair(&mut rng).unwrap();
    let (pk_b, _sk_b) = generate_keypair(&mut rng).unwrap();

    let enc_a = encapsulate(&mut rng, &pk_a).unwrap();
    let enc_b = encapsulate(&mut rng, &pk_b).unwrap();

    assert_ne!(
        enc_a.shared_secret.as_slice(),
        enc_b.shared_secret.as_slice(),
        "Different keypairs should produce different shared secrets"
    );
}

#[test]
fn test_kem_cross_key_rejection() {
    let mut rng = OsRng;
    let (pk_a, _sk_a) = generate_keypair(&mut rng).unwrap();
    let (_pk_b, sk_b) = generate_keypair(&mut rng).unwrap();

    // Encapsulate with key A
    let enc_key = encapsulate(&mut rng, &pk_a).unwrap();

    // Decapsulate with key B — should produce a different shared secret
    // (ML-KEM implicit rejection returns a valid but wrong secret)
    let dec_secret_b = decapsulate(&sk_b, &enc_key).unwrap();
    assert_ne!(
        dec_secret_b.as_slice(),
        enc_key.shared_secret.as_slice(),
        "Cross-key decapsulation should yield a different shared secret"
    );
}

// ============================================================================
// Encryption Roundtrip Tests
// ============================================================================

#[test]
fn test_encrypt_decrypt_roundtrip() {
    let mut rng = OsRng;
    let (pk, sk) = generate_keypair(&mut rng).unwrap();

    let plaintext = b"Hello, hybrid encryption!";
    let context = HybridEncryptionContext::default();

    let ct =
        encrypt_hybrid(&mut rng, &pk, plaintext, Some(&context)).expect("encrypt should succeed");
    let decrypted = decrypt_hybrid(&sk, &ct, Some(&context)).expect("decrypt should succeed");

    assert_eq!(decrypted.as_slice(), plaintext, "Roundtrip plaintext mismatch");
}

#[test]
fn test_encrypt_decrypt_with_aad() {
    let mut rng = OsRng;
    let (pk, sk) = generate_keypair(&mut rng).unwrap();

    let plaintext = b"data with additional authenticated data";
    let context = HybridEncryptionContext {
        info: b"custom-domain-separation".to_vec(),
        aad: b"header-metadata-v2".to_vec(),
    };

    let ct = encrypt_hybrid(&mut rng, &pk, plaintext, Some(&context)).unwrap();
    let decrypted = decrypt_hybrid(&sk, &ct, Some(&context)).unwrap();

    assert_eq!(decrypted.as_slice(), plaintext);
}

#[test]
fn test_encrypt_decrypt_empty_plaintext() {
    let mut rng = OsRng;
    let (pk, sk) = generate_keypair(&mut rng).unwrap();

    let plaintext = b"";
    let context = HybridEncryptionContext::default();

    let ct = encrypt_hybrid(&mut rng, &pk, plaintext, Some(&context)).unwrap();
    let decrypted = decrypt_hybrid(&sk, &ct, Some(&context)).unwrap();

    assert!(decrypted.is_empty(), "Empty plaintext should decrypt to empty");
}

#[test]
fn test_encrypt_decrypt_large_plaintext() {
    let mut rng = OsRng;
    let (pk, sk) = generate_keypair(&mut rng).unwrap();

    // 64KB payload
    let plaintext: Vec<u8> = (0..65_536u32).map(|i| (i & 0xFF) as u8).collect();
    let context = HybridEncryptionContext::default();

    let ct = encrypt_hybrid(&mut rng, &pk, &plaintext, Some(&context)).unwrap();
    let decrypted = decrypt_hybrid(&sk, &ct, Some(&context)).unwrap();

    assert_eq!(decrypted, plaintext, "64KB roundtrip mismatch");
}

#[test]
fn test_encrypt_decrypt_many_messages() {
    let mut rng = OsRng;
    let (pk, sk) = generate_keypair(&mut rng).unwrap();
    let context = HybridEncryptionContext::default();

    for i in 0..50u32 {
        let msg = format!("Message number {} with varying length data!", i);
        let ct = encrypt_hybrid(&mut rng, &pk, msg.as_bytes(), Some(&context))
            .unwrap_or_else(|e| panic!("encrypt {} failed: {:?}", i, e));
        let dec = decrypt_hybrid(&sk, &ct, Some(&context))
            .unwrap_or_else(|e| panic!("decrypt {} failed: {:?}", i, e));
        assert_eq!(dec, msg.as_bytes(), "Message {} roundtrip mismatch", i);
    }
}

#[test]
fn test_encrypt_wrong_key_fails() {
    let mut rng = OsRng;
    let (pk_a, _sk_a) = generate_keypair(&mut rng).unwrap();
    let (_pk_b, sk_b) = generate_keypair(&mut rng).unwrap();

    let plaintext = b"secret data";
    let context = HybridEncryptionContext::default();

    let ct = encrypt_hybrid(&mut rng, &pk_a, plaintext, Some(&context)).unwrap();

    // Decrypt with wrong key — should fail (AEAD authentication)
    let result = decrypt_hybrid(&sk_b, &ct, Some(&context));
    assert!(result.is_err(), "Decryption with wrong key should fail");
}

// ============================================================================
// Tamper Detection Tests
// ============================================================================

#[test]
fn test_tampered_kem_ciphertext_fails() {
    let mut rng = OsRng;
    let (pk, sk) = generate_keypair(&mut rng).unwrap();
    let context = HybridEncryptionContext::default();

    let mut ct = encrypt_hybrid(&mut rng, &pk, b"test", Some(&context)).unwrap();

    // Flip a byte in the ML-KEM ciphertext
    if !ct.kem_ciphertext.is_empty() {
        ct.kem_ciphertext[0] ^= 0xFF;
    }

    let result = decrypt_hybrid(&sk, &ct, Some(&context));
    assert!(result.is_err(), "Tampered KEM ciphertext should fail decryption");
}

#[test]
fn test_tampered_ecdh_pk_fails() {
    let mut rng = OsRng;
    let (pk, sk) = generate_keypair(&mut rng).unwrap();
    let context = HybridEncryptionContext::default();

    let mut ct = encrypt_hybrid(&mut rng, &pk, b"test", Some(&context)).unwrap();

    // Flip a byte in the ephemeral ECDH public key
    if !ct.ecdh_ephemeral_pk.is_empty() {
        ct.ecdh_ephemeral_pk[0] ^= 0xFF;
    }

    let result = decrypt_hybrid(&sk, &ct, Some(&context));
    assert!(result.is_err(), "Tampered ECDH PK should fail decryption");
}

#[test]
fn test_tampered_symmetric_ciphertext_fails() {
    let mut rng = OsRng;
    let (pk, sk) = generate_keypair(&mut rng).unwrap();
    let context = HybridEncryptionContext::default();

    let mut ct = encrypt_hybrid(&mut rng, &pk, b"test data here", Some(&context)).unwrap();

    // Flip a byte in the AES-GCM ciphertext
    if !ct.symmetric_ciphertext.is_empty() {
        ct.symmetric_ciphertext[0] ^= 0xFF;
    }

    let result = decrypt_hybrid(&sk, &ct, Some(&context));
    assert!(result.is_err(), "Tampered symmetric ciphertext should fail");
}

#[test]
fn test_tampered_nonce_fails() {
    let mut rng = OsRng;
    let (pk, sk) = generate_keypair(&mut rng).unwrap();
    let context = HybridEncryptionContext::default();

    let mut ct = encrypt_hybrid(&mut rng, &pk, b"test", Some(&context)).unwrap();

    // Alter the nonce
    if !ct.nonce.is_empty() {
        ct.nonce[0] ^= 0xFF;
    }

    let result = decrypt_hybrid(&sk, &ct, Some(&context));
    assert!(result.is_err(), "Tampered nonce should fail decryption");
}

#[test]
fn test_tampered_tag_fails() {
    let mut rng = OsRng;
    let (pk, sk) = generate_keypair(&mut rng).unwrap();
    let context = HybridEncryptionContext::default();

    let mut ct = encrypt_hybrid(&mut rng, &pk, b"test", Some(&context)).unwrap();

    // Alter the authentication tag
    if !ct.tag.is_empty() {
        ct.tag[0] ^= 0xFF;
    }

    let result = decrypt_hybrid(&sk, &ct, Some(&context));
    assert!(result.is_err(), "Tampered tag should fail decryption");
}

// ============================================================================
// Signature Roundtrip Tests
// ============================================================================

#[test]
fn test_sig_generate_sign_verify() {
    let mut rng = OsRng;
    let (pk, sk) = sig::generate_keypair(&mut rng).expect("keygen should succeed");

    let message = b"Document to sign with hybrid ML-DSA + Ed25519";
    let signature = sig::sign(&sk, message).expect("signing should succeed");
    let is_valid = sig::verify(&pk, message, &signature).expect("verify should succeed");

    assert!(is_valid, "Valid signature should verify");
}

#[test]
fn test_sig_persistent_identity() {
    let mut rng = OsRng;
    let (pk, sk) = sig::generate_keypair(&mut rng).unwrap();

    // Sign 20 messages with the same keypair
    for i in 0..20u32 {
        let msg = format!("Persistent identity message {}", i);
        let signature =
            sig::sign(&sk, msg.as_bytes()).unwrap_or_else(|e| panic!("sign {} failed: {:?}", i, e));
        let is_valid = sig::verify(&pk, msg.as_bytes(), &signature)
            .unwrap_or_else(|e| panic!("verify {} failed: {:?}", i, e));
        assert!(is_valid, "Message {} should verify", i);
    }
}

#[test]
fn test_sig_cross_key_rejection() {
    let mut rng = OsRng;
    let (_pk_a, sk_a) = sig::generate_keypair(&mut rng).unwrap();
    let (pk_b, _sk_b) = sig::generate_keypair(&mut rng).unwrap();

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
fn test_complete_hybrid_workflow() {
    let mut rng = OsRng;

    // Step 1: Generate KEM keypair
    let (kem_pk, kem_sk) = generate_keypair(&mut rng).unwrap();

    // Step 2: Generate signature keypair
    let (sig_pk, sig_sk) = sig::generate_keypair(&mut rng).unwrap();

    // Step 3: Encapsulate to derive shared secret
    let enc_key = encapsulate(&mut rng, &kem_pk).unwrap();
    let shared_secret = enc_key.shared_secret.as_slice().to_vec();

    // Step 4: Encrypt a message using the hybrid encryption API
    let plaintext = b"Complete hybrid workflow test: KEM + Encrypt + Sign + Verify + Decrypt";
    let context = HybridEncryptionContext::default();
    let ct = encrypt_hybrid(&mut rng, &kem_pk, plaintext, Some(&context)).unwrap();

    // Step 5: Sign the ciphertext for non-repudiation
    // Serialize a simple representation of the ciphertext for signing
    let ct_bytes_for_sig = [
        ct.kem_ciphertext.as_slice(),
        ct.ecdh_ephemeral_pk.as_slice(),
        ct.symmetric_ciphertext.as_slice(),
    ]
    .concat();
    let signature = sig::sign(&sig_sk, &ct_bytes_for_sig).unwrap();

    // Step 6: Verify the signature
    let sig_valid = sig::verify(&sig_pk, &ct_bytes_for_sig, &signature).unwrap();
    assert!(sig_valid, "Ciphertext signature should verify");

    // Step 7: Decapsulate shared secret
    let dec_secret = decapsulate(&kem_sk, &enc_key).unwrap();
    assert_eq!(dec_secret, shared_secret, "Shared secrets should match");

    // Step 8: Decrypt the message
    let decrypted = decrypt_hybrid(&kem_sk, &ct, Some(&context)).unwrap();
    assert_eq!(decrypted.as_slice(), plaintext, "Full workflow roundtrip mismatch");
}
