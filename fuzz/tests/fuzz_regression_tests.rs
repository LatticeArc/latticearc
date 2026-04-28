//! Fuzz Regression Tests
//!
//! This module contains regression tests for edge cases discovered through
//! fuzzing. These tests guard against reintroduction of specific failure modes.
//!
//! # Organization
//!
//! Tests are organized by cryptographic primitive:
//! - ML-KEM (FIPS 203) - Key encapsulation
//! - ML-DSA (FIPS 204) - Digital signatures
//! - SLH-DSA (FIPS 205) - Hash-based signatures
//! - AES-GCM - Authenticated encryption
//! - ChaCha20-Poly1305 - Authenticated encryption
//! - Hash functions - SHA-2, SHA-3
//! - Key derivation - HKDF, PBKDF2
//! - HMAC - Message authentication
//!
//! # Running Regression Tests
//!
//! ```bash
//! cargo test --package fuzz --test fuzz_regression_tests
//! ```

use latticearc::primitives::aead::AeadCipher;
use latticearc::primitives::aead::aes_gcm::{AesGcm128, AesGcm256};
use latticearc::primitives::aead::chacha20poly1305::ChaCha20Poly1305Cipher;
use latticearc::primitives::hash::{sha2::sha256, sha2::sha384, sha2::sha512, sha3::sha3_256};
use latticearc::primitives::kdf::hkdf::hkdf;
use latticearc::primitives::kem::ml_kem::{
    MlKem, MlKemCiphertext, MlKemPublicKey, MlKemSecurityLevel,
};
use latticearc::primitives::mac::hmac::{hmac_sha256, verify_hmac_sha256};
use latticearc::primitives::sig::ml_dsa::{
    MlDsaParameterSet, MlDsaSignature, generate_keypair as ml_dsa_generate,
};
use latticearc::primitives::sig::slh_dsa::{
    SigningKey, SlhDsaSecurityLevel as SlhDsaLevel, VerifyingKey,
};

// ============================================================================
// ML-KEM Regression Tests
// ============================================================================

mod ml_kem_regression {
    use super::*;

    /// Test that ML-KEM rejects public keys with incorrect sizes
    #[test]
    fn test_ml_kem_invalid_pk_size_512_fails() {
        let result = MlKemPublicKey::new(MlKemSecurityLevel::MlKem512, vec![0u8; 799]);
        assert!(result.is_err(), "Should reject 799-byte key for ML-KEM-512 (requires 800)");

        let result = MlKemPublicKey::new(MlKemSecurityLevel::MlKem512, vec![0u8; 801]);
        assert!(result.is_err(), "Should reject 801-byte key for ML-KEM-512 (requires 800)");
    }

    /// Test that ML-KEM rejects ciphertexts with incorrect sizes
    #[test]
    fn test_ml_kem_invalid_ct_size_768_fails() {
        let result = MlKemCiphertext::new(MlKemSecurityLevel::MlKem768, vec![0u8; 1087]);
        assert!(
            result.is_err(),
            "Should reject 1087-byte ciphertext for ML-KEM-768 (requires 1088)"
        );

        let result = MlKemCiphertext::new(MlKemSecurityLevel::MlKem768, vec![0u8; 1089]);
        assert!(
            result.is_err(),
            "Should reject 1089-byte ciphertext for ML-KEM-768 (requires 1088)"
        );
    }

    /// Test ML-KEM-1024 parameter validation
    #[test]
    fn test_ml_kem_1024_parameters_succeeds() {
        let level = MlKemSecurityLevel::MlKem1024;
        assert_eq!(level.public_key_size(), 1568);
        assert_eq!(level.secret_key_size(), 3168);
        assert_eq!(level.ciphertext_size(), 1568);
        assert_eq!(level.shared_secret_size(), 32);
    }

    /// Test that encapsulation produces consistent ciphertext sizes.
    ///
    /// A previous version of this test wrapped the assertions in
    /// `if let Ok(...)` with no `else` branch, so the test would silently
    /// pass if keygen or encapsulation ever broke — a regression meant to
    /// detect failures could no longer detect the most important one.
    /// We now unwrap: ML-KEM keygen and encapsulate are infallible for the
    /// fixed security levels used here, and a failure here is a real
    /// library bug the hook should surface.
    #[test]
    fn test_ml_kem_encapsulation_sizes_has_correct_size() {
        for level in [
            MlKemSecurityLevel::MlKem512,
            MlKemSecurityLevel::MlKem768,
            MlKemSecurityLevel::MlKem1024,
        ] {
            let (pk, _sk) = MlKem::generate_keypair(level)
                .unwrap_or_else(|e| panic!("keygen failed for {level:?}: {e}"));
            let (ss, ct) = MlKem::encapsulate(&pk)
                .unwrap_or_else(|e| panic!("encapsulate failed for {level:?}: {e}"));
            assert_eq!(ss.expose_secret().len(), 32, "shared secret must be 32 bytes");
            assert_eq!(
                ct.as_bytes().len(),
                level.ciphertext_size(),
                "ciphertext size mismatch for {level:?}",
            );
        }
    }

    /// Regression: All-zero public key handling
    ///
    /// An all-zero public key is structurally valid (correct length) but
    /// cryptographically degenerate. The library must not crash when
    /// encapsulating against it — either a clean error or a well-formed
    /// (but insecure) ciphertext is acceptable.
    #[test]
    fn test_ml_kem_zero_public_key_succeeds() {
        let zero_pk = MlKemPublicKey::new(MlKemSecurityLevel::MlKem768, vec![0u8; 1184]);
        if let Ok(pk) = zero_pk {
            let _ = MlKem::encapsulate(&pk);
        }
    }
}

// ============================================================================
// ML-DSA Regression Tests
// ============================================================================

mod ml_dsa_regression {
    use super::*;

    /// Flip one byte of an ML-DSA signature and return a new, unchecked
    /// `MlDsaSignature` carrying the corrupted bytes.
    ///
    /// `MlDsaSignature` stores its bytes in a private field, so corruption
    /// tests can't mutate in place — they rebuild the signature via
    /// `from_bytes_unchecked`, which preserves the tamper but keeps the
    /// length invariant intact.
    fn flip_byte(sig: &MlDsaSignature, offset: usize) -> MlDsaSignature {
        let mut bytes = sig.to_bytes();
        bytes[offset] ^= 0xFF;
        MlDsaSignature::from_bytes_unchecked(sig.parameter_set(), bytes)
    }

    /// Test ML-DSA signature corruption detection
    #[test]
    fn test_ml_dsa_corrupted_signature_bytes_fails() {
        let (pk, sk) = ml_dsa_generate(MlDsaParameterSet::MlDsa44).unwrap();
        let message = b"Test message for corruption detection";
        let sig = sk.sign(message, &[]).unwrap();

        // Corruption patterns that should all fail verification
        let corruption_offsets = [0, 100, 500, 1000, sig.len() - 1];

        for offset in corruption_offsets {
            if offset < sig.len() {
                let corrupted = flip_byte(&sig, offset);
                let result = pk.verify(message, &corrupted, &[]).unwrap();
                assert!(!result, "Corrupted signature at offset {} must fail", offset);
            }
        }
    }

    /// Test context string boundary (max 255 bytes per FIPS 204)
    #[test]
    fn test_ml_dsa_context_boundary_succeeds() {
        let (pk, sk) = ml_dsa_generate(MlDsaParameterSet::MlDsa44).unwrap();
        let message = b"Context boundary test";

        // Max context (255 bytes) should work
        let max_context = vec![0xAB; 255];
        let sig = sk.sign(message, &max_context).unwrap();
        assert!(pk.verify(message, &sig, &max_context).unwrap());
    }

    /// Regression: Empty message signing
    #[test]
    fn test_ml_dsa_empty_message_succeeds() {
        for param in
            [MlDsaParameterSet::MlDsa44, MlDsaParameterSet::MlDsa65, MlDsaParameterSet::MlDsa87]
        {
            let (pk, sk) = ml_dsa_generate(param).unwrap();
            let sig = sk.sign(&[], &[]).unwrap();
            assert!(pk.verify(&[], &sig, &[]).unwrap());
        }
    }

    /// Regression: Cross-parameter set rejection
    #[test]
    fn test_ml_dsa_cross_parameter_rejection_fails() {
        let (_pk44, sk44) = ml_dsa_generate(MlDsaParameterSet::MlDsa44).unwrap();
        let (pk65, _sk65) = ml_dsa_generate(MlDsaParameterSet::MlDsa65).unwrap();
        let message = b"Cross-parameter test";

        let sig44 = sk44.sign(message, &[]).unwrap();

        // Verification with wrong parameter set public key
        let result = pk65.verify(message, &sig44, &[]);
        // Should either error or return false
        match result {
            Ok(valid) => assert!(!valid),
            Err(_) => {} // Error is also acceptable
        }
    }
}

// ============================================================================
// SLH-DSA Regression Tests
// ============================================================================

mod slh_dsa_regression {
    use super::*;

    /// Test SLH-DSA context string handling
    #[test]
    fn test_slh_dsa_context_variations_succeeds() {
        let (sk, pk) = SigningKey::generate(SlhDsaLevel::Shake128s).unwrap();
        let message = b"Context test message";

        // Empty context
        let sig_empty = sk.sign(message, &[]).unwrap();
        assert!(pk.verify(message, &sig_empty, &[]).unwrap());

        // Non-empty context
        let ctx = b"test context";
        let sig_ctx = sk.sign(message, ctx).unwrap();
        assert!(pk.verify(message, &sig_ctx, ctx).unwrap());

        // Cross-verification must fail
        assert!(!pk.verify(message, &sig_empty, ctx).unwrap());
        assert!(!pk.verify(message, &sig_ctx, &[]).unwrap());
    }

    /// Regression: Context too long (>255 bytes)
    #[test]
    fn test_slh_dsa_context_too_long_succeeds() {
        let (sk, _pk) = SigningKey::generate(SlhDsaLevel::Shake128s).unwrap();
        let message = b"Long context test";
        let long_ctx = vec![0xCD; 256];

        let result = sk.sign(message, &long_ctx);
        assert!(result.is_err(), "Context >255 bytes should fail");
    }

    /// Test verifying key reconstruction from bytes
    #[test]
    fn test_slh_dsa_key_serialization_succeeds() {
        let (sk, pk) = SigningKey::generate(SlhDsaLevel::Shake128s).unwrap();

        // Serialize and deserialize public key
        let pk_bytes = pk.to_bytes();
        let pk_restored = VerifyingKey::from_bytes(&pk_bytes, SlhDsaLevel::Shake128s).unwrap();

        // Sign and verify with restored key
        let message = b"Key serialization test";
        let sig = sk.sign(message, &[]).unwrap();
        assert!(pk_restored.verify(message, &sig, &[]).unwrap());
    }
}

// ============================================================================
// AEAD Regression Tests
// ============================================================================

mod aead_regression {
    use super::*;

    /// Regression: Empty plaintext encryption
    #[test]
    fn test_aes_gcm_empty_plaintext_succeeds() {
        let key = AesGcm256::generate_key();
        let cipher = AesGcm256::new(&*key).unwrap();
        let nonce = AesGcm256::generate_nonce();

        let (ct, tag) = cipher.encrypt(&nonce, &[], None).unwrap();
        assert!(ct.is_empty(), "Empty plaintext should produce empty ciphertext");
        assert_eq!(tag.len(), 16, "Tag should still be 16 bytes");

        let decrypted = cipher.decrypt(&nonce, &ct, &tag, None).unwrap();
        assert!(decrypted.is_empty());
    }

    /// Regression: AAD mismatch detection
    #[test]
    fn test_aes_gcm_aad_mismatch_fails() {
        let key = AesGcm128::generate_key();
        let cipher = AesGcm128::new(&*key).unwrap();
        let nonce = AesGcm128::generate_nonce();
        let plaintext = b"AAD mismatch test";
        let aad = b"correct AAD";

        let (ct, tag) = cipher.encrypt(&nonce, plaintext, Some(aad)).unwrap();

        // Wrong AAD
        let wrong_aad = b"wrong AAD";
        let result = cipher.decrypt(&nonce, &ct, &tag, Some(wrong_aad));
        assert!(result.is_err(), "Wrong AAD must fail decryption");

        // No AAD when expected
        let result = cipher.decrypt(&nonce, &ct, &tag, None);
        assert!(result.is_err(), "Missing AAD must fail decryption");
    }

    /// Regression: ChaCha20-Poly1305 nonce uniqueness
    #[test]
    fn test_chacha_nonce_produces_different_ct_succeeds() {
        let key = [0x42u8; 32];
        let cipher = ChaCha20Poly1305Cipher::new(&key).unwrap();
        let plaintext = b"Nonce uniqueness test";

        let nonce1 = [0x01u8; 12];
        let nonce2 = [0x02u8; 12];

        let (ct1, _tag1) = cipher.encrypt(&nonce1, plaintext, None).unwrap();
        let (ct2, _tag2) = cipher.encrypt(&nonce2, plaintext, None).unwrap();

        assert_ne!(ct1, ct2, "Different nonces must produce different ciphertexts");
    }

    /// Regression: Invalid key length rejection
    #[test]
    fn test_aead_invalid_key_lengths_fails() {
        // AES-128 requires 16-byte key
        assert!(AesGcm128::new(&[0u8; 15]).is_err());
        assert!(AesGcm128::new(&[0u8; 17]).is_err());

        // AES-256 requires 32-byte key
        assert!(AesGcm256::new(&[0u8; 31]).is_err());
        assert!(AesGcm256::new(&[0u8; 33]).is_err());
    }

    /// Regression: ChaCha20-Poly1305 invalid key length rejection
    #[test]
    fn test_chacha_invalid_key_lengths_fails() {
        assert!(ChaCha20Poly1305Cipher::new(&[0u8; 31]).is_err());
        assert!(ChaCha20Poly1305Cipher::new(&[0u8; 33]).is_err());
    }
}

// ============================================================================
// Hash Function Regression Tests
// ============================================================================

mod hash_regression {
    use super::*;

    /// Test hash function determinism
    #[test]
    fn test_hash_determinism_is_deterministic() {
        let data = b"Determinism test data";

        assert_eq!(sha256(data).unwrap(), sha256(data).unwrap());
        assert_eq!(sha384(data).unwrap(), sha384(data).unwrap());
        assert_eq!(sha512(data).unwrap(), sha512(data).unwrap());
        assert_eq!(sha3_256(data), sha3_256(data));
    }

    /// Test hash function output lengths
    #[test]
    fn test_hash_output_lengths_has_correct_size() {
        let data = b"Length test";

        assert_eq!(sha256(data).unwrap().len(), 32);
        assert_eq!(sha384(data).unwrap().len(), 48);
        assert_eq!(sha512(data).unwrap().len(), 64);
        assert_eq!(sha3_256(data).len(), 32);
    }

    /// Test empty input hashing
    #[test]
    fn test_hash_empty_input_fails() {
        let empty = &[];

        // SHA-256 of empty string is a well-known value
        let hash = sha256(empty).unwrap();
        assert_eq!(hash.len(), 32);

        // All hash functions should handle empty input
        assert_eq!(sha384(empty).unwrap().len(), 48);
        assert_eq!(sha512(empty).unwrap().len(), 64);
        assert_eq!(sha3_256(empty).len(), 32);
    }

    /// Regression: SHA-2 vs SHA-3 must produce different outputs
    #[test]
    fn test_sha2_sha3_different_succeeds() {
        let data = b"SHA family comparison";
        let sha2_hash = sha256(data).unwrap();
        let sha3_hash = sha3_256(data);

        assert_ne!(
            sha2_hash.as_slice(),
            sha3_hash.as_slice(),
            "SHA-256 and SHA3-256 must produce different hashes"
        );
    }
}

// ============================================================================
// Key Derivation Regression Tests
// ============================================================================

mod kdf_regression {
    use super::*;

    /// Test HKDF determinism
    #[test]
    fn test_hkdf_determinism_is_deterministic() {
        let ikm = b"input key material";
        let salt = b"salt value";
        let info = b"info string";

        let result1 = hkdf(ikm, Some(salt), Some(info), 32).unwrap();
        let result2 = hkdf(ikm, Some(salt), Some(info), 32).unwrap();

        assert_eq!(result1.expose_secret(), result2.expose_secret(), "HKDF must be deterministic");
    }

    /// Test HKDF domain separation
    #[test]
    fn test_hkdf_domain_separation_succeeds() {
        let ikm = b"shared key material";
        let salt = b"salt";
        let info1 = b"context 1";
        let info2 = b"context 2";

        let result1 = hkdf(ikm, Some(salt), Some(info1), 32).unwrap();
        let result2 = hkdf(ikm, Some(salt), Some(info2), 32).unwrap();

        assert_ne!(
            result1.expose_secret(),
            result2.expose_secret(),
            "Different info must produce different keys"
        );
    }

    /// Regression: HKDF output length validation
    #[test]
    fn test_hkdf_max_output_length_has_correct_size() {
        let ikm = b"test ikm";
        let salt = b"test salt";
        let info = b"test info";

        // Max output for HKDF-SHA256 is 255 * 32 = 8160 bytes
        let max_len = 255 * 32;
        let result = hkdf(ikm, Some(salt), Some(info), max_len);
        assert!(result.is_ok(), "Max output length should succeed");

        // Exceeding max should fail
        let result = hkdf(ikm, Some(salt), Some(info), max_len + 1);
        assert!(result.is_err(), "Exceeding max output length should fail");
    }
}

// ============================================================================
// HMAC Regression Tests
// ============================================================================

mod hmac_regression {
    use super::*;

    /// Test HMAC verification
    #[test]
    fn test_hmac_verification_succeeds() {
        let key = b"secret key";
        let message = b"message to authenticate";

        let tag = hmac_sha256(key, message).unwrap();
        assert!(verify_hmac_sha256(key, message, &tag));

        // Wrong key
        assert!(!verify_hmac_sha256(b"wrong key", message, &tag));

        // Wrong message
        assert!(!verify_hmac_sha256(key, b"wrong message", &tag));

        // Corrupted tag
        let mut corrupted = tag;
        corrupted[0] ^= 0xFF;
        assert!(!verify_hmac_sha256(key, message, &corrupted));
    }

    /// Regression: Empty key and message handling.
    ///
    /// `hmac_sha256` rejects an empty key (RFC 2104 allows any length but
    /// the library enforces a ≥ 1-byte minimum as a safety guard — an
    /// all-empty key is never meaningful). An empty message is accepted.
    #[test]
    fn test_hmac_empty_inputs_fails() {
        // Empty key — must be rejected.
        assert!(hmac_sha256(&[], b"message").is_err(), "Empty HMAC key must be rejected");

        // Empty message with non-empty key — must succeed.
        assert!(hmac_sha256(b"key", &[]).is_ok(), "Empty message with valid key must succeed");

        // Both empty — rejected because key is empty.
        assert!(
            hmac_sha256(&[], &[]).is_err(),
            "Empty key + empty message must be rejected (empty key)"
        );
    }

    /// Test HMAC tag truncation detection
    #[test]
    fn test_hmac_truncated_tag_succeeds() {
        let key = b"test key";
        let message = b"test message";

        let tag = hmac_sha256(key, message).unwrap();
        let truncated = &tag[..16];

        // Verification with truncated tag should fail
        assert!(!verify_hmac_sha256(key, message, truncated));
    }
}

// ============================================================================
// Corpus Management Helpers
// ============================================================================

/// Helper module for managing fuzz corpus
pub mod corpus_helpers {
    use std::fs;
    use std::path::Path;

    /// Creates a corpus directory if it doesn't exist
    pub fn ensure_corpus_dir(target_name: &str) -> std::io::Result<()> {
        let corpus_dir = format!("corpus/{}", target_name);
        fs::create_dir_all(&corpus_dir)?;
        Ok(())
    }

    /// Adds a test case to the corpus
    pub fn add_to_corpus(target_name: &str, data: &[u8], name: &str) -> std::io::Result<()> {
        let corpus_dir = format!("corpus/{}", target_name);
        fs::create_dir_all(&corpus_dir)?;

        let path = format!("{}/{}", corpus_dir, name);
        fs::write(path, data)?;
        Ok(())
    }

    /// Lists all corpus files for a target
    pub fn list_corpus(target_name: &str) -> std::io::Result<Vec<String>> {
        let corpus_dir = format!("corpus/{}", target_name);
        let path = Path::new(&corpus_dir);

        if !path.exists() {
            return Ok(vec![]);
        }

        let entries: Vec<String> = fs::read_dir(path)?
            .filter_map(|e| e.ok())
            .filter_map(|e| e.path().to_str().map(String::from))
            .collect();

        Ok(entries)
    }

    /// Removes duplicate corpus entries (by hash)
    pub fn deduplicate_corpus(target_name: &str) -> std::io::Result<usize> {
        use std::collections::HashSet;

        let corpus_dir = format!("corpus/{}", target_name);
        let path = Path::new(&corpus_dir);

        if !path.exists() {
            return Ok(0);
        }

        let mut seen_hashes: HashSet<Vec<u8>> = HashSet::new();
        let mut removed = 0;

        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let file_path = entry.path();

            if let Ok(data) = fs::read(&file_path) {
                if let Ok(hash_arr) = super::sha256(&data) {
                    let hash = hash_arr.to_vec();

                    if seen_hashes.contains(&hash) {
                        fs::remove_file(&file_path)?;
                        removed += 1;
                    } else {
                        seen_hashes.insert(hash);
                    }
                }
            }
        }

        Ok(removed)
    }
}
