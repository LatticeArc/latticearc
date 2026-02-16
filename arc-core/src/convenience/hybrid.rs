//! Hybrid encryption combining ML-KEM-768 + X25519 + HKDF + AES-256-GCM
//!
//! This module provides true hybrid encryption where the shared secret is derived
//! from both a post-quantum KEM (ML-KEM-768) and a classical ECDH (X25519) via
//! HKDF-SHA256. Security holds if *either* algorithm remains secure.
//!
//! ## Key Generation
//!
//! ```rust,ignore
//! use arc_core::{generate_hybrid_keypair, encrypt_hybrid, decrypt_hybrid, SecurityMode};
//!
//! let (pk, sk) = generate_hybrid_keypair()?;
//! let encrypted = encrypt_hybrid(b"secret", &pk, SecurityMode::Unverified)?;
//! let decrypted = decrypt_hybrid(&encrypted, &sk, SecurityMode::Unverified)?;
//! ```
//!
//! ## Encryption Pipeline
//!
//! 1. ML-KEM-768 encapsulation → shared secret 1
//! 2. X25519 ephemeral ECDH → shared secret 2
//! 3. HKDF-SHA256(ss1 || ss2) → 256-bit data encryption key
//! 4. AES-256-GCM encrypt plaintext with derived key

use arc_hybrid::encrypt_hybrid::{
    HybridCiphertext as ArcHybridCiphertext, decrypt_hybrid as arc_hybrid_decrypt,
    encrypt_hybrid as arc_hybrid_encrypt,
};
use arc_hybrid::kem_hybrid::{
    self as kem, HybridPublicKey as KemHybridPublicKey, HybridSecretKey as KemHybridSecretKey,
};

use crate::error::{CoreError, Result};
use crate::zero_trust::SecurityMode;

use arc_types::resource_limits::{validate_decryption_size, validate_encryption_size};

/// Result of hybrid encryption (ML-KEM-768 + X25519 + AES-256-GCM).
///
/// Contains all components needed for decryption: the KEM ciphertext,
/// the ephemeral ECDH public key, and the AES-256-GCM encrypted payload.
#[derive(Debug)]
pub struct HybridEncryptionResult {
    /// ML-KEM ciphertext (1088 bytes for ML-KEM-768).
    pub kem_ciphertext: Vec<u8>,
    /// X25519 ephemeral public key (32 bytes).
    pub ecdh_ephemeral_pk: Vec<u8>,
    /// AES-256-GCM encrypted data.
    pub symmetric_ciphertext: Vec<u8>,
    /// AES-GCM nonce (12 bytes).
    pub nonce: Vec<u8>,
    /// AES-GCM authentication tag (16 bytes).
    pub tag: Vec<u8>,
}

/// Generate a hybrid keypair (ML-KEM-768 + X25519).
///
/// Returns a public key (for encryption) and a secret key (for decryption).
/// The keypair combines post-quantum and classical algorithms for defense in depth.
///
/// # Errors
///
/// Returns an error if key generation fails.
pub fn generate_hybrid_keypair() -> Result<(KemHybridPublicKey, KemHybridSecretKey)> {
    let mut rng = rand::rngs::OsRng;
    kem::generate_keypair(&mut rng).map_err(|e| {
        CoreError::EncryptionFailed(format!("Hybrid keypair generation failed: {}", e))
    })
}

/// Encrypt data using hybrid encryption (ML-KEM-768 + X25519 + AES-256-GCM).
///
/// The shared secret is derived from both ML-KEM (post-quantum) and X25519
/// (classical) via HKDF-SHA256. Security holds if *either* algorithm remains
/// secure.
///
/// # Errors
///
/// Returns an error if:
/// - The session has expired (when `mode` is `Verified`)
/// - Data size exceeds resource limits
/// - Hybrid KEM encapsulation fails
/// - AES-GCM encryption fails
pub fn encrypt_hybrid(
    data: &[u8],
    hybrid_pk: &KemHybridPublicKey,
    mode: SecurityMode,
) -> Result<HybridEncryptionResult> {
    mode.validate()?;

    validate_encryption_size(data.len()).map_err(|e| CoreError::ResourceExceeded(e.to_string()))?;

    let mut rng = rand::rngs::OsRng;
    let ct = arc_hybrid_encrypt(&mut rng, hybrid_pk, data, None)
        .map_err(|e| CoreError::EncryptionFailed(format!("Hybrid encryption failed: {}", e)))?;

    Ok(HybridEncryptionResult {
        kem_ciphertext: ct.kem_ciphertext,
        ecdh_ephemeral_pk: ct.ecdh_ephemeral_pk,
        symmetric_ciphertext: ct.symmetric_ciphertext,
        nonce: ct.nonce,
        tag: ct.tag,
    })
}

/// Decrypt data using hybrid encryption (ML-KEM-768 + X25519 + AES-256-GCM).
///
/// # Errors
///
/// Returns an error if:
/// - The session has expired (when `mode` is `Verified`)
/// - Ciphertext size exceeds resource limits
/// - Hybrid KEM decapsulation fails
/// - AES-GCM decryption or authentication fails
pub fn decrypt_hybrid(
    encrypted: &HybridEncryptionResult,
    hybrid_sk: &KemHybridSecretKey,
    mode: SecurityMode,
) -> Result<Vec<u8>> {
    mode.validate()?;

    validate_decryption_size(encrypted.symmetric_ciphertext.len())
        .map_err(|e| CoreError::ResourceExceeded(e.to_string()))?;

    let ct = ArcHybridCiphertext {
        kem_ciphertext: encrypted.kem_ciphertext.clone(),
        ecdh_ephemeral_pk: encrypted.ecdh_ephemeral_pk.clone(),
        symmetric_ciphertext: encrypted.symmetric_ciphertext.clone(),
        nonce: encrypted.nonce.clone(),
        tag: encrypted.tag.clone(),
    };

    arc_hybrid_decrypt(hybrid_sk, &ct, None)
        .map_err(|e| CoreError::DecryptionFailed(format!("Hybrid decryption failed: {}", e)))
}

/// Encrypt data using hybrid encryption with configuration.
///
/// # Errors
///
/// Returns an error if session validation, config validation, or encryption fails.
#[inline]
pub fn encrypt_hybrid_with_config(
    data: &[u8],
    hybrid_pk: &KemHybridPublicKey,
    config: &crate::config::CoreConfig,
    mode: SecurityMode,
) -> Result<HybridEncryptionResult> {
    config.validate()?;
    encrypt_hybrid(data, hybrid_pk, mode)
}

/// Decrypt data using hybrid encryption with configuration.
///
/// # Errors
///
/// Returns an error if session validation, config validation, or decryption fails.
#[inline]
pub fn decrypt_hybrid_with_config(
    encrypted: &HybridEncryptionResult,
    hybrid_sk: &KemHybridSecretKey,
    config: &crate::config::CoreConfig,
    mode: SecurityMode,
) -> Result<Vec<u8>> {
    config.validate()?;
    decrypt_hybrid(encrypted, hybrid_sk, mode)
}

// ============================================================================
// Unverified Convenience Variants
// ============================================================================

/// Encrypt without Zero Trust verification.
///
/// # Errors
///
/// Returns an error if encryption fails.
#[inline]
pub fn encrypt_hybrid_unverified(
    data: &[u8],
    hybrid_pk: &KemHybridPublicKey,
) -> Result<HybridEncryptionResult> {
    encrypt_hybrid(data, hybrid_pk, SecurityMode::Unverified)
}

/// Decrypt without Zero Trust verification.
///
/// # Errors
///
/// Returns an error if decryption fails.
#[inline]
pub fn decrypt_hybrid_unverified(
    encrypted: &HybridEncryptionResult,
    hybrid_sk: &KemHybridSecretKey,
) -> Result<Vec<u8>> {
    decrypt_hybrid(encrypted, hybrid_sk, SecurityMode::Unverified)
}

/// Encrypt with config without Zero Trust verification.
///
/// # Errors
///
/// Returns an error if config validation or encryption fails.
#[inline]
pub fn encrypt_hybrid_with_config_unverified(
    data: &[u8],
    hybrid_pk: &KemHybridPublicKey,
    config: &crate::config::CoreConfig,
) -> Result<HybridEncryptionResult> {
    encrypt_hybrid_with_config(data, hybrid_pk, config, SecurityMode::Unverified)
}

/// Decrypt with config without Zero Trust verification.
///
/// # Errors
///
/// Returns an error if config validation or decryption fails.
#[inline]
pub fn decrypt_hybrid_with_config_unverified(
    encrypted: &HybridEncryptionResult,
    hybrid_sk: &KemHybridSecretKey,
    config: &crate::config::CoreConfig,
) -> Result<Vec<u8>> {
    decrypt_hybrid_with_config(encrypted, hybrid_sk, config, SecurityMode::Unverified)
}

// The unified API (api.rs) with `&[u8]` keys only supports AES-256-GCM symmetric
// encryption. When the selector picks a hybrid scheme (which it does by default),
// the unified API falls back to AES-256-GCM automatically.
//
// For true PQ+classical hybrid encryption (ML-KEM-768 + X25519 + HKDF + AES-256-GCM),
// use the typed API: encrypt_hybrid() / decrypt_hybrid() with HybridPublicKey/HybridSecretKey.

#[cfg(test)]
#[allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic_in_result_fn,
    clippy::unnecessary_wraps,
    clippy::redundant_clone,
    clippy::useless_vec,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::clone_on_copy,
    clippy::len_zero,
    clippy::single_match,
    clippy::unnested_or_patterns,
    clippy::default_constructed_unit_structs,
    clippy::redundant_closure_for_method_calls,
    clippy::semicolon_if_nothing_returned,
    clippy::unnecessary_unwrap,
    clippy::redundant_pattern_matching,
    clippy::missing_const_for_thread_local,
    clippy::get_first,
    clippy::float_cmp,
    clippy::needless_borrows_for_generic_args,
    unused_qualifications
)]
mod tests {
    use super::*;

    #[test]
    fn test_hybrid_roundtrip() -> Result<()> {
        let (pk, sk) = generate_hybrid_keypair()?;

        let message = b"Hybrid encryption roundtrip test";
        let encrypted = encrypt_hybrid(message, &pk, SecurityMode::Unverified)?;

        assert_eq!(encrypted.kem_ciphertext.len(), 1088);
        assert_eq!(encrypted.ecdh_ephemeral_pk.len(), 32);
        assert!(!encrypted.symmetric_ciphertext.is_empty());
        assert_eq!(encrypted.nonce.len(), 12);
        assert_eq!(encrypted.tag.len(), 16);

        let decrypted = decrypt_hybrid(&encrypted, &sk, SecurityMode::Unverified)?;
        assert_eq!(decrypted, message);
        Ok(())
    }

    #[test]
    fn test_hybrid_large_message() -> Result<()> {
        let (pk, sk) = generate_hybrid_keypair()?;

        let message = vec![0xAB; 10_000];
        let encrypted = encrypt_hybrid(&message, &pk, SecurityMode::Unverified)?;
        let decrypted = decrypt_hybrid(&encrypted, &sk, SecurityMode::Unverified)?;

        assert_eq!(decrypted, message);
        Ok(())
    }

    #[test]
    fn test_hybrid_multiple_encryptions() -> Result<()> {
        let (pk, sk) = generate_hybrid_keypair()?;

        for i in 0..5 {
            let message = format!("Message {}", i);
            let encrypted = encrypt_hybrid(message.as_bytes(), &pk, SecurityMode::Unverified)?;
            let decrypted = decrypt_hybrid(&encrypted, &sk, SecurityMode::Unverified)?;
            assert_eq!(decrypted, message.as_bytes());
        }
        Ok(())
    }

    #[test]
    fn test_hybrid_non_deterministic() -> Result<()> {
        let (pk, _sk) = generate_hybrid_keypair()?;

        let message = b"Same message";
        let enc1 = encrypt_hybrid(message, &pk, SecurityMode::Unverified)?;
        let enc2 = encrypt_hybrid(message, &pk, SecurityMode::Unverified)?;

        assert_ne!(enc1.kem_ciphertext, enc2.kem_ciphertext);
        assert_ne!(enc1.ecdh_ephemeral_pk, enc2.ecdh_ephemeral_pk);
        Ok(())
    }

    #[test]
    fn test_hybrid_unverified_convenience() -> Result<()> {
        let (pk, sk) = generate_hybrid_keypair()?;

        let message = b"Unverified convenience test";
        let encrypted = encrypt_hybrid_unverified(message, &pk)?;
        let decrypted = decrypt_hybrid_unverified(&encrypted, &sk)?;

        assert_eq!(decrypted, message);
        Ok(())
    }

    #[test]
    fn test_hybrid_with_config() -> Result<()> {
        let (pk, sk) = generate_hybrid_keypair()?;
        let config = crate::config::CoreConfig::default();

        let message = b"Config test";
        let encrypted = encrypt_hybrid_with_config_unverified(message, &pk, &config)?;
        let decrypted = decrypt_hybrid_with_config_unverified(&encrypted, &sk, &config)?;

        assert_eq!(decrypted, message);
        Ok(())
    }

    #[test]
    fn test_hybrid_empty_message() -> Result<()> {
        let (pk, sk) = generate_hybrid_keypair()?;

        let message = b"";
        let encrypted = encrypt_hybrid(message, &pk, SecurityMode::Unverified)?;
        let decrypted = decrypt_hybrid(&encrypted, &sk, SecurityMode::Unverified)?;

        assert_eq!(decrypted, message);
        Ok(())
    }
}
