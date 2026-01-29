#![deny(unsafe_code)]
#![warn(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

//! # Unified Elliptic Curve Traits
//!
//! Trait-based API for consistent elliptic curve operations across different curves.
//! Following RustCrypto patterns with Result-based error handling.

use arc_prelude::error::Result;

/// Unified elliptic curve key pair trait
pub trait EcKeyPair: Send + Sync {
    /// Public key type
    type PublicKey: Clone + Send + Sync;

    /// Secret key type
    type SecretKey: Send + Sync;

    /// Generate a new random key pair
    ///
    /// # Errors
    /// Returns an error if key generation fails.
    fn generate() -> Result<Self>
    where
        Self: Sized;

    /// Create key pair from secret key bytes
    ///
    /// # Errors
    /// Returns an error if the secret key bytes are invalid.
    fn from_secret_key(secret_key: &[u8]) -> Result<Self>
    where
        Self: Sized;

    /// Get the public key
    fn public_key(&self) -> &Self::PublicKey;

    /// Get the secret key (for signing/encryption operations)
    fn secret_key(&self) -> &Self::SecretKey;

    /// Export public key as bytes
    fn public_key_bytes(&self) -> Vec<u8>;

    /// Export secret key as bytes (use with caution)
    fn secret_key_bytes(&self) -> Vec<u8>;
}

/// Unified elliptic curve signature trait
pub trait EcSignature: Send + Sync {
    /// Signature type
    type Signature: Clone + Send + Sync;

    /// Sign a message using the secret key
    ///
    /// # Errors
    /// Returns an error if signing fails.
    fn sign(&self, message: &[u8]) -> Result<Self::Signature>;

    /// Verify a signature against a message and public key
    ///
    /// # Errors
    /// Returns an error if verification fails or the signature is invalid.
    fn verify(public_key: &[u8], message: &[u8], signature: &Self::Signature) -> Result<()>;

    /// Get signature length in bytes
    fn signature_len() -> usize;

    /// Export signature as bytes
    fn signature_bytes(signature: &Self::Signature) -> Vec<u8>;

    /// Import signature from bytes
    ///
    /// # Errors
    /// Returns an error if the signature bytes are malformed.
    fn signature_from_bytes(bytes: &[u8]) -> Result<Self::Signature>;
}
