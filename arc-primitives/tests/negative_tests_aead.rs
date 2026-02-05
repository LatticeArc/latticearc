#![allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_lossless,
    clippy::redundant_clone,
    clippy::clone_on_copy,
    clippy::collapsible_if,
    clippy::single_match,
    clippy::needless_range_loop,
    clippy::explicit_iter_loop,
    clippy::explicit_auto_deref,
    clippy::assertions_on_constants,
    clippy::len_zero,
    clippy::print_stdout,
    clippy::unused_unit,
    clippy::expect_fun_call,
    clippy::useless_vec,
    clippy::cloned_instead_of_copied,
    clippy::float_cmp,
    clippy::needless_borrows_for_generic_args,
    clippy::manual_let_else
)]
//! Comprehensive negative tests for arc-primitives AEAD implementations
//!
//! This test suite validates error handling at the primitives layer for AES-GCM
//! and ChaCha20-Poly1305 authenticated encryption.
//!
//! Test coverage:
//! - Invalid key lengths
//! - Invalid nonce sizes
//! - Corrupted ciphertexts and tags
//! - Empty inputs
//! - Boundary conditions

use arc_primitives::aead::{
    AeadCipher, AeadError,
    aes_gcm::{AesGcm128, AesGcm256},
    chacha20poly1305::ChaCha20Poly1305Cipher,
};

// ============================================================================
// AES-GCM-128 Negative Tests
// ============================================================================

#[test]
fn test_aes_gcm_128_empty_key() {
    let empty_key = [];
    let result = AesGcm128::new(&empty_key);
    assert!(result.is_err(), "Should fail with empty key");

    match result {
        Err(AeadError::InvalidKeyLength) => {
            // Expected error
        }
        _ => panic!("Expected InvalidKeyLength error"),
    }
}

#[test]
fn test_aes_gcm_128_short_key() {
    let short_key = [0u8; 8]; // Need 16 bytes
    let result = AesGcm128::new(&short_key);
    assert!(result.is_err(), "Should fail with short key");

    match result {
        Err(AeadError::InvalidKeyLength) => {
            // Expected error
        }
        _ => panic!("Expected InvalidKeyLength error"),
    }
}

#[test]
fn test_aes_gcm_128_15_byte_key() {
    let key = [0u8; 15]; // One byte short
    let result = AesGcm128::new(&key);
    assert!(result.is_err(), "Should fail with 15-byte key");

    match result {
        Err(AeadError::InvalidKeyLength) => {
            // Expected error
        }
        _ => panic!("Expected InvalidKeyLength error"),
    }
}

#[test]
fn test_aes_gcm_128_17_byte_key() {
    let key = [0u8; 17]; // One byte too long
    let result = AesGcm128::new(&key);
    assert!(result.is_err(), "Should fail with 17-byte key");

    match result {
        Err(AeadError::InvalidKeyLength) => {
            // Expected error
        }
        _ => panic!("Expected InvalidKeyLength error"),
    }
}

#[test]
fn test_aes_gcm_128_decrypt_corrupted_tag() {
    let key = [0u8; 16];
    let cipher = AesGcm128::new(&key).expect("cipher creation should succeed");

    let nonce = AesGcm128::generate_nonce();
    let plaintext = b"secret message";
    let (ciphertext, mut tag) =
        cipher.encrypt(&nonce, plaintext, None).expect("encryption should succeed");

    // Corrupt the tag
    tag[0] ^= 0xFF;

    let result = cipher.decrypt(&nonce, &ciphertext, &tag, None);
    assert!(result.is_err(), "Should fail with corrupted tag");

    match result {
        Err(AeadError::DecryptionFailed(_)) => {
            // Expected error - authentication failure
        }
        _ => panic!("Expected DecryptionFailed error"),
    }
}

#[test]
fn test_aes_gcm_128_decrypt_corrupted_ciphertext() {
    let key = [0u8; 16];
    let cipher = AesGcm128::new(&key).expect("cipher creation should succeed");

    let nonce = AesGcm128::generate_nonce();
    let plaintext = b"secret message";
    let (mut ciphertext, tag) =
        cipher.encrypt(&nonce, plaintext, None).expect("encryption should succeed");

    // Corrupt the ciphertext
    if !ciphertext.is_empty() {
        ciphertext[0] ^= 0xFF;
    }

    let result = cipher.decrypt(&nonce, &ciphertext, &tag, None);
    assert!(result.is_err(), "Should fail with corrupted ciphertext");

    match result {
        Err(AeadError::DecryptionFailed(_)) => {
            // Expected error - authentication failure
        }
        _ => panic!("Expected DecryptionFailed error"),
    }
}

#[test]
fn test_aes_gcm_128_decrypt_wrong_nonce() {
    let key = [0u8; 16];
    let cipher = AesGcm128::new(&key).expect("cipher creation should succeed");

    let nonce1 = AesGcm128::generate_nonce();
    let plaintext = b"secret message";
    let (ciphertext, tag) =
        cipher.encrypt(&nonce1, plaintext, None).expect("encryption should succeed");

    let nonce2 = AesGcm128::generate_nonce();

    let result = cipher.decrypt(&nonce2, &ciphertext, &tag, None);
    assert!(result.is_err(), "Should fail with wrong nonce");

    match result {
        Err(AeadError::DecryptionFailed(_)) => {
            // Expected error - authentication failure
        }
        _ => panic!("Expected DecryptionFailed error"),
    }
}

#[test]
fn test_aes_gcm_128_decrypt_empty_ciphertext_corrupted_tag() {
    let key = [0u8; 16];
    let cipher = AesGcm128::new(&key).expect("cipher creation should succeed");

    let nonce = AesGcm128::generate_nonce();
    let plaintext = b"";
    let (ciphertext, mut tag) =
        cipher.encrypt(&nonce, plaintext, None).expect("encryption should succeed");

    // Corrupt the tag for empty ciphertext
    tag[0] ^= 0xFF;

    let result = cipher.decrypt(&nonce, &ciphertext, &tag, None);
    assert!(result.is_err(), "Should fail with corrupted tag even for empty ciphertext");

    match result {
        Err(AeadError::DecryptionFailed(_)) => {
            // Expected error
        }
        _ => panic!("Expected DecryptionFailed error"),
    }
}

// ============================================================================
// AES-GCM-256 Negative Tests
// ============================================================================

#[test]
fn test_aes_gcm_256_empty_key() {
    let empty_key = [];
    let result = AesGcm256::new(&empty_key);
    assert!(result.is_err(), "Should fail with empty key");

    match result {
        Err(AeadError::InvalidKeyLength) => {
            // Expected error
        }
        _ => panic!("Expected InvalidKeyLength error"),
    }
}

#[test]
fn test_aes_gcm_256_short_key() {
    let short_key = [0u8; 16]; // Need 32 bytes
    let result = AesGcm256::new(&short_key);
    assert!(result.is_err(), "Should fail with short key");

    match result {
        Err(AeadError::InvalidKeyLength) => {
            // Expected error
        }
        _ => panic!("Expected InvalidKeyLength error"),
    }
}

#[test]
fn test_aes_gcm_256_31_byte_key() {
    let key = [0u8; 31]; // One byte short
    let result = AesGcm256::new(&key);
    assert!(result.is_err(), "Should fail with 31-byte key");

    match result {
        Err(AeadError::InvalidKeyLength) => {
            // Expected error
        }
        _ => panic!("Expected InvalidKeyLength error"),
    }
}

#[test]
fn test_aes_gcm_256_33_byte_key() {
    let key = [0u8; 33]; // One byte too long
    let result = AesGcm256::new(&key);
    assert!(result.is_err(), "Should fail with 33-byte key");

    match result {
        Err(AeadError::InvalidKeyLength) => {
            // Expected error
        }
        _ => panic!("Expected InvalidKeyLength error"),
    }
}

#[test]
fn test_aes_gcm_256_decrypt_corrupted_tag() {
    let key = [0u8; 32];
    let cipher = AesGcm256::new(&key).expect("cipher creation should succeed");

    let nonce = AesGcm256::generate_nonce();
    let plaintext = b"secret message";
    let (ciphertext, mut tag) =
        cipher.encrypt(&nonce, plaintext, None).expect("encryption should succeed");

    // Corrupt the tag
    tag[15] ^= 0xFF;

    let result = cipher.decrypt(&nonce, &ciphertext, &tag, None);
    assert!(result.is_err(), "Should fail with corrupted tag");

    match result {
        Err(AeadError::DecryptionFailed(_)) => {
            // Expected error
        }
        _ => panic!("Expected DecryptionFailed error"),
    }
}

#[test]
fn test_aes_gcm_256_decrypt_all_zeros_tag() {
    let key = [0u8; 32];
    let cipher = AesGcm256::new(&key).expect("cipher creation should succeed");

    let nonce = AesGcm256::generate_nonce();
    let plaintext = b"secret message";
    let (ciphertext, _tag) =
        cipher.encrypt(&nonce, plaintext, None).expect("encryption should succeed");

    // Use all-zeros tag
    let zero_tag = [0u8; 16];

    let result = cipher.decrypt(&nonce, &ciphertext, &zero_tag, None);
    assert!(result.is_err(), "Should fail with all-zeros tag");

    match result {
        Err(AeadError::DecryptionFailed(_)) => {
            // Expected error
        }
        _ => panic!("Expected DecryptionFailed error"),
    }
}

// ============================================================================
// ChaCha20-Poly1305 Negative Tests
// ============================================================================

#[test]
fn test_chacha20_poly1305_empty_key() {
    let empty_key = [];
    let result = ChaCha20Poly1305Cipher::new(&empty_key);
    assert!(result.is_err(), "Should fail with empty key");

    match result {
        Err(AeadError::InvalidKeyLength) => {
            // Expected error
        }
        _ => panic!("Expected InvalidKeyLength error"),
    }
}

#[test]
fn test_chacha20_poly1305_short_key() {
    let short_key = [0u8; 16]; // Need 32 bytes
    let result = ChaCha20Poly1305Cipher::new(&short_key);
    assert!(result.is_err(), "Should fail with short key");

    match result {
        Err(AeadError::InvalidKeyLength) => {
            // Expected error
        }
        _ => panic!("Expected InvalidKeyLength error"),
    }
}

#[test]
fn test_chacha20_poly1305_31_byte_key() {
    let key = [0u8; 31]; // One byte short
    let result = ChaCha20Poly1305Cipher::new(&key);
    assert!(result.is_err(), "Should fail with 31-byte key");

    match result {
        Err(AeadError::InvalidKeyLength) => {
            // Expected error
        }
        _ => panic!("Expected InvalidKeyLength error"),
    }
}

#[test]
fn test_chacha20_poly1305_33_byte_key() {
    let key = [0u8; 33]; // One byte too long
    let result = ChaCha20Poly1305Cipher::new(&key);
    assert!(result.is_err(), "Should fail with 33-byte key");

    match result {
        Err(AeadError::InvalidKeyLength) => {
            // Expected error
        }
        _ => panic!("Expected InvalidKeyLength error"),
    }
}

#[test]
fn test_chacha20_poly1305_decrypt_corrupted_tag() {
    let key = [0u8; 32];
    let cipher = ChaCha20Poly1305Cipher::new(&key).expect("cipher creation should succeed");

    let nonce = ChaCha20Poly1305Cipher::generate_nonce();
    let plaintext = b"secret message";
    let (ciphertext, mut tag) =
        cipher.encrypt(&nonce, plaintext, None).expect("encryption should succeed");

    // Corrupt the tag
    tag[0] ^= 0xFF;

    let result = cipher.decrypt(&nonce, &ciphertext, &tag, None);
    assert!(result.is_err(), "Should fail with corrupted tag");

    match result {
        Err(AeadError::DecryptionFailed(_)) => {
            // Expected error
        }
        _ => panic!("Expected DecryptionFailed error"),
    }
}

#[test]
fn test_chacha20_poly1305_decrypt_corrupted_ciphertext() {
    let key = [0u8; 32];
    let cipher = ChaCha20Poly1305Cipher::new(&key).expect("cipher creation should succeed");

    let nonce = ChaCha20Poly1305Cipher::generate_nonce();
    let plaintext = b"secret message with sufficient length";
    let (mut ciphertext, tag) =
        cipher.encrypt(&nonce, plaintext, None).expect("encryption should succeed");

    // Corrupt the ciphertext
    if ciphertext.len() > 10 {
        ciphertext[10] ^= 0xFF;
    }

    let result = cipher.decrypt(&nonce, &ciphertext, &tag, None);
    assert!(result.is_err(), "Should fail with corrupted ciphertext");

    match result {
        Err(AeadError::DecryptionFailed(_)) => {
            // Expected error
        }
        _ => panic!("Expected DecryptionFailed error"),
    }
}

#[test]
fn test_chacha20_poly1305_decrypt_wrong_key() {
    let key1 = [0x00u8; 32];
    let key2 = [0xFFu8; 32];

    let cipher1 = ChaCha20Poly1305Cipher::new(&key1).expect("cipher creation should succeed");
    let cipher2 = ChaCha20Poly1305Cipher::new(&key2).expect("cipher creation should succeed");

    let nonce = ChaCha20Poly1305Cipher::generate_nonce();
    let plaintext = b"secret message";
    let (ciphertext, tag) =
        cipher1.encrypt(&nonce, plaintext, None).expect("encryption should succeed");

    // Try to decrypt with different key
    let result = cipher2.decrypt(&nonce, &ciphertext, &tag, None);
    assert!(result.is_err(), "Should fail with wrong key");

    match result {
        Err(AeadError::DecryptionFailed(_)) => {
            // Expected error
        }
        _ => panic!("Expected DecryptionFailed error"),
    }
}

// ============================================================================
// Cross-Algorithm Tests
// ============================================================================

#[test]
fn test_aes_128_encrypt_chacha_decrypt() {
    let key = [0u8; 32]; // Both use 32-byte keys (use first 16 for AES-128)
    let aes_key = &key[..16];

    let aes_cipher = AesGcm128::new(aes_key).expect("AES cipher creation should succeed");
    let chacha_cipher =
        ChaCha20Poly1305Cipher::new(&key).expect("ChaCha cipher creation should succeed");

    let nonce = [0u8; 12]; // Same nonce size
    let plaintext = b"secret message";
    let (ciphertext, tag) =
        aes_cipher.encrypt(&nonce, plaintext, None).expect("encryption should succeed");

    // Try to decrypt AES ciphertext with ChaCha20
    let result = chacha_cipher.decrypt(&nonce, &ciphertext, &tag, None);
    assert!(result.is_err(), "Should fail when mixing algorithms");

    match result {
        Err(AeadError::DecryptionFailed(_)) => {
            // Expected error
        }
        _ => panic!("Expected DecryptionFailed error"),
    }
}

// ============================================================================
// Additional Authenticated Data (AAD) Tests
// ============================================================================

#[test]
fn test_aes_gcm_256_decrypt_wrong_aad() {
    let key = [0u8; 32];
    let cipher = AesGcm256::new(&key).expect("cipher creation should succeed");

    let nonce = AesGcm256::generate_nonce();
    let plaintext = b"secret message";
    let aad1 = b"metadata1";
    let (ciphertext, tag) =
        cipher.encrypt(&nonce, plaintext, Some(aad1)).expect("encryption should succeed");

    // Try to decrypt with different AAD
    let aad2 = b"metadata2";
    let result = cipher.decrypt(&nonce, &ciphertext, &tag, Some(aad2));
    assert!(result.is_err(), "Should fail with wrong AAD");

    match result {
        Err(AeadError::DecryptionFailed(_)) => {
            // Expected error - AAD mismatch
        }
        _ => panic!("Expected DecryptionFailed error"),
    }
}

#[test]
fn test_chacha20_poly1305_decrypt_missing_aad() {
    let key = [0u8; 32];
    let cipher = ChaCha20Poly1305Cipher::new(&key).expect("cipher creation should succeed");

    let nonce = ChaCha20Poly1305Cipher::generate_nonce();
    let plaintext = b"secret message";
    let aad = b"important metadata";
    let (ciphertext, tag) =
        cipher.encrypt(&nonce, plaintext, Some(aad)).expect("encryption should succeed");

    // Try to decrypt without AAD
    let result = cipher.decrypt(&nonce, &ciphertext, &tag, None);
    assert!(result.is_err(), "Should fail when AAD is missing");

    match result {
        Err(AeadError::DecryptionFailed(_)) => {
            // Expected error
        }
        _ => panic!("Expected DecryptionFailed error"),
    }
}

#[test]
fn test_aes_gcm_128_decrypt_unexpected_aad() {
    let key = [0u8; 16];
    let cipher = AesGcm128::new(&key).expect("cipher creation should succeed");

    let nonce = AesGcm128::generate_nonce();
    let plaintext = b"secret message";
    // Encrypt without AAD
    let (ciphertext, tag) =
        cipher.encrypt(&nonce, plaintext, None).expect("encryption should succeed");

    // Try to decrypt with AAD
    let aad = b"unexpected metadata";
    let result = cipher.decrypt(&nonce, &ciphertext, &tag, Some(aad));
    assert!(result.is_err(), "Should fail when unexpected AAD is provided");

    match result {
        Err(AeadError::DecryptionFailed(_)) => {
            // Expected error
        }
        _ => panic!("Expected DecryptionFailed error"),
    }
}

// ============================================================================
// Boundary Conditions
// ============================================================================

#[test]
fn test_aes_gcm_256_encrypt_empty_plaintext() {
    let key = [0u8; 32];
    let cipher = AesGcm256::new(&key).expect("cipher creation should succeed");

    let nonce = AesGcm256::generate_nonce();
    let plaintext = b"";

    // Encrypting empty plaintext should succeed
    let result = cipher.encrypt(&nonce, plaintext, None);
    assert!(result.is_ok(), "Should succeed with empty plaintext");

    let (ciphertext, tag) = result.expect("already checked");
    assert!(ciphertext.is_empty(), "Ciphertext should be empty");
    assert_eq!(tag.len(), 16, "Tag should still be 16 bytes");

    // Decrypt should work
    let decrypted =
        cipher.decrypt(&nonce, &ciphertext, &tag, None).expect("decryption should succeed");
    assert!(decrypted.is_empty(), "Decrypted should be empty");
}

#[test]
fn test_chacha20_poly1305_encrypt_single_byte() {
    let key = [0u8; 32];
    let cipher = ChaCha20Poly1305Cipher::new(&key).expect("cipher creation should succeed");

    let nonce = ChaCha20Poly1305Cipher::generate_nonce();
    let plaintext = [0x42u8];

    let (ciphertext, tag) =
        cipher.encrypt(&nonce, &plaintext, None).expect("encryption should succeed");
    let decrypted =
        cipher.decrypt(&nonce, &ciphertext, &tag, None).expect("decryption should succeed");

    assert_eq!(decrypted, plaintext, "Single byte should round-trip");
}
