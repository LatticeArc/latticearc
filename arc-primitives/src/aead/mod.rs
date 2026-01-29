#![deny(unsafe_code)]
#![warn(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

//! Authenticated Encryption with Additional Data (AEAD)
//!
//! Provides AEAD schemes for symmetric encryption following NIST SP 800-38D and RFC 8439.
//!
//! ## AEAD Schemes
//!
//! - **AES-GCM-128**: AES-GCM with 128-bit key (NIST SP 800-38D)
//! - **AES-GCM-256**: AES-GCM with 256-bit key (NIST SP 800-38D)
//! - **ChaCha20-Poly1305**: Stream cipher with Poly1305 MAC (RFC 8439)
//!
//! ## AEAD Security Notes
//!
//! - **Nonce Reuse**: NEVER reuse a nonce with the same key - this breaks security
//! - **Nonce Prediction**: Use cryptographically secure random nonces
//! - **Tag Verification**: ALWAYS verify the authentication tag before accepting ciphertext
//! - **Side Channels**: All tag verification is constant-time to prevent timing attacks

pub mod aes_gcm;
pub mod chacha20poly1305;

/// AEAD cipher nonce length
pub const NONCE_LEN: usize = 12;

/// AEAD authentication tag length
pub const TAG_LEN: usize = 16;

/// AES-GCM-128 key length
pub const AES_GCM_128_KEY_LEN: usize = 16;

/// AES-GCM-256 key length
pub const AES_GCM_256_KEY_LEN: usize = 32;

/// ChaCha20-Poly1305 key length
pub const CHACHA20_POLY1305_KEY_LEN: usize = 32;

/// Nonce type for AEAD ciphers
pub type Nonce = [u8; NONCE_LEN];

/// Auth tag type for AEAD ciphers
pub type Tag = [u8; TAG_LEN];

/// AEAD cipher trait
pub trait AeadCipher {
    /// Key length in bytes
    const KEY_LEN: usize;

    /// Create new AEAD cipher from key bytes.
    ///
    /// # Errors
    /// Returns an error if the key length does not match the expected size for this cipher.
    fn new(key: &[u8]) -> Result<Self, AeadError>
    where
        Self: Sized;

    /// Generate a random nonce
    fn generate_nonce() -> Nonce;

    /// Encrypt plaintext with optional associated data
    ///
    /// # Arguments
    ///
    /// * `nonce` - Unique nonce for this encryption (must be 12 bytes)
    /// * `plaintext` - Data to encrypt
    /// * `aad` - Optional associated data (authenticated but not encrypted)
    ///
    /// # Returns
    ///
    /// Tuple of (ciphertext, authentication_tag)
    ///
    /// # Errors
    ///
    /// Returns `AeadError` if encryption fails
    fn encrypt(
        &self,
        nonce: &Nonce,
        plaintext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<(Vec<u8>, Tag), AeadError>;

    /// Decrypt ciphertext with optional associated data
    ///
    /// # Arguments
    ///
    /// * `nonce` - Unique nonce for this encryption
    /// * `ciphertext` - Encrypted data
    /// * `tag` - Authentication tag
    /// * `aad` - Optional associated data
    ///
    /// # Returns
    ///
    /// Decrypted plaintext
    ///
    /// # Errors
    ///
    /// Returns `AeadError` if decryption fails
    fn decrypt(
        &self,
        nonce: &Nonce,
        ciphertext: &[u8],
        tag: &Tag,
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, AeadError>;
}

/// AEAD errors
#[derive(Debug, thiserror::Error)]
pub enum AeadError {
    /// Invalid key length
    #[error("Invalid key length")]
    InvalidKeyLength,

    /// Invalid nonce length
    #[error("Invalid nonce length")]
    InvalidNonceLength,

    /// Invalid tag length
    #[error("Invalid tag length")]
    InvalidTagLength,

    /// Authentication tag verification failed
    #[error("Authentication tag verification failed")]
    TagVerificationFailed,

    /// Encryption failed
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    /// Decryption failed
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),

    /// Other error
    #[error("AEAD error: {0}")]
    Other(String),
}

// Re-export ChaCha20-Poly1305 cipher types for convenience
pub use self::chacha20poly1305::{ChaCha20Poly1305Cipher, XChaCha20Poly1305Cipher};

#[cfg(test)]
#[allow(unused_imports)] // Some re-exported types may not be directly used in tests
mod tests {
    use super::*;

    // Helper: constant-time tag comparison (available for future tests)
    #[allow(dead_code)]
    fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
        use subtle::ConstantTimeEq;
        let len_eq = a.len().ct_eq(&b.len());
        let mut result = len_eq;
        for (x, y) in a.iter().zip(b.iter()) {
            result &= x.ct_eq(y);
        }
        result.into()
    }
}
