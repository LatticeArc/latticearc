#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

//! # Unified Elliptic Curve Traits
//!
//! Trait-based API for consistent elliptic curve operations across different curves.
//! Following RustCrypto patterns with Result-based error handling.

use crate::prelude::error::Result;
use zeroize::Zeroizing;

pub(super) mod sealed {
    /// Sealing trait — prevents external implementations of [`super::EcKeyPair`]
    /// and [`super::EcSignature`].
    pub trait Sealed {}
}

/// Unified elliptic curve key pair trait.
///
/// This trait operates purely on byte slices at its public surface to avoid
/// leaking backing-crate types (e.g., `ed25519_dalek::SigningKey`,
/// `k256::ecdsa::VerifyingKey`) across the API boundary. Concrete implementations
/// may expose backend-native accessors as inherent methods if needed.
pub trait EcKeyPair: Send + Sync + sealed::Sealed {
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

    /// Export public key as bytes
    fn public_key_bytes(&self) -> Vec<u8>;

    /// Export secret key as bytes wrapped in [`Zeroizing`] for automatic cleanup on drop.
    fn secret_key_bytes(&self) -> Zeroizing<Vec<u8>>;
}

/// Unified elliptic curve signature verification trait
///
/// Signing requires access to a secret key and is handled by [`EcKeyPair`]
/// implementations directly (e.g., `Ed25519KeyPair::sign`).
pub trait EcSignature: Send + Sync + sealed::Sealed {
    /// Signature type
    type Signature: Clone + Send + Sync;

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
