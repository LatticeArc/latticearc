#![deny(unsafe_code)]
#![warn(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]
// JUSTIFICATION: SLH-DSA has fixed-size keys/signatures per security level.
// All indexing is bounded by validated lengths checked before access.
// The fips205 crate handles the actual cryptographic operations.
#![allow(clippy::indexing_slicing)]

//! SLH-DSA (Stateless Hash-Based Digital Signature Algorithm)
//!
//! This module provides SLH-DSA signatures as specified in FIPS 205.
//! All cryptographic operations use the audited `fips205` crate.
//!
//! # Security Levels
//!
//! - **SLH-DSA-SHAKE-128s**: NIST security level 1 (quantum security ~128 bits)
//! - **SLH-DSA-SHAKE-192s**: NIST security level 3 (quantum security ~192 bits)
//! - **SLH-DSA-SHAKE-256s**: NIST security level 5 (quantum security ~256 bits)
//!
//! # Example
//!
//! ```rust
//! use arc_primitives::sig::slh_dsa::{SecurityLevel, SigningKey, VerifyingKey};
//!
//! // Generate a key pair
//! let (signing_key, verifying_key) = SigningKey::generate(SecurityLevel::Shake128s)?;
//!
//! // Sign a message (None = no context string)
//! let message = b"Hello, SLH-DSA!";
//! let signature = signing_key.sign(message, None)?;
//!
//! // Verify the signature (None = no context string)
//! let is_valid = verifying_key.verify(message, &signature, None)?;
//! assert!(is_valid);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use fips205::slh_dsa_shake_128s as shake_128s;
use fips205::slh_dsa_shake_192s as shake_192s;
use fips205::slh_dsa_shake_256s as shake_256s;
use fips205::traits::{SerDes, Signer, Verifier};
use subtle::{Choice, ConstantTimeEq};
use tracing::instrument;
use zeroize::Zeroize;

use thiserror::Error;

// ============================================================================
// Error Types
// ============================================================================

/// Errors that can occur in SLH-DSA operations
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum SlhDsaError {
    /// Random number generation failed
    #[error("Random number generation failed")]
    RngError,

    /// Invalid public key (malformed or corrupted)
    #[error("Invalid public key")]
    InvalidPublicKey,

    /// Invalid secret key (malformed or corrupted)
    #[error("Invalid secret key")]
    InvalidSecretKey,

    /// Signature verification failed
    #[error("Signature verification failed")]
    VerificationFailed,

    /// Serialization failed
    #[error("Serialization failed")]
    SerializationError,

    /// Deserialization failed
    #[error("Deserialization failed")]
    DeserializationError,

    /// Context string too long (max 255 bytes)
    #[error("Context string too long (max 255 bytes)")]
    ContextTooLong,
}

// ============================================================================
// Security Levels
// ============================================================================

/// SLH-DSA security levels as specified in FIPS 205
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum SecurityLevel {
    /// SLH-DSA-SHAKE-128s: NIST Level 1 (quantum security ~128 bits)
    /// Smaller keys and signatures, faster performance
    Shake128s = 1,

    /// SLH-DSA-SHAKE-192s: NIST Level 3 (quantum security ~192 bits)
    /// Balanced security and performance
    Shake192s = 2,

    /// SLH-DSA-SHAKE-256s: NIST Level 5 (quantum security ~256 bits)
    /// Highest security, larger keys and signatures
    Shake256s = 3,
}

impl SecurityLevel {
    /// Returns the NIST security level (1-5)
    #[must_use]
    pub const fn nist_level(&self) -> u8 {
        match self {
            SecurityLevel::Shake128s => 1,
            SecurityLevel::Shake192s => 3,
            SecurityLevel::Shake256s => 5,
        }
    }

    /// Returns the public key size in bytes
    #[must_use]
    pub const fn public_key_size(&self) -> usize {
        match self {
            SecurityLevel::Shake128s => shake_128s::PK_LEN,
            SecurityLevel::Shake192s => shake_192s::PK_LEN,
            SecurityLevel::Shake256s => shake_256s::PK_LEN,
        }
    }

    /// Returns the secret key size in bytes
    #[must_use]
    pub const fn secret_key_size(&self) -> usize {
        match self {
            SecurityLevel::Shake128s => shake_128s::SK_LEN,
            SecurityLevel::Shake192s => shake_192s::SK_LEN,
            SecurityLevel::Shake256s => shake_256s::SK_LEN,
        }
    }

    /// Returns the signature size in bytes
    #[must_use]
    pub const fn signature_size(&self) -> usize {
        match self {
            SecurityLevel::Shake128s => shake_128s::SIG_LEN,
            SecurityLevel::Shake192s => shake_192s::SIG_LEN,
            SecurityLevel::Shake256s => shake_256s::SIG_LEN,
        }
    }
}

// ============================================================================
// Verifying Key (Public Key)
// ============================================================================

/// SLH-DSA verifying key (public key)
///
/// This is a wrapper around the audited fips205 crate's public key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyingKey {
    /// The security level used
    security_level: SecurityLevel,

    /// The underlying public key bytes
    bytes: [u8; shake_256s::PK_LEN], // Max size for all variants

    /// The actual length of the public key
    len: usize,
}

impl VerifyingKey {
    /// Creates a new verifying key from bytes
    ///
    /// # Errors
    /// Returns an error if the key length is incorrect or the key is malformed.
    pub fn new(security_level: SecurityLevel, bytes: &[u8]) -> Result<Self, SlhDsaError> {
        let expected_len = security_level.public_key_size();
        if bytes.len() != expected_len {
            return Err(SlhDsaError::InvalidPublicKey);
        }

        let mut key_bytes = [0u8; shake_256s::PK_LEN];
        key_bytes[..expected_len].copy_from_slice(bytes);

        match security_level {
            SecurityLevel::Shake128s => {
                let pk_bytes: [u8; shake_128s::PK_LEN] =
                    bytes.try_into().map_err(|_e| SlhDsaError::DeserializationError)?;
                shake_128s::PublicKey::try_from_bytes(&pk_bytes)
                    .map_err(|_e| SlhDsaError::InvalidPublicKey)?;
            }
            SecurityLevel::Shake192s => {
                let pk_bytes: [u8; shake_192s::PK_LEN] =
                    bytes.try_into().map_err(|_e| SlhDsaError::DeserializationError)?;
                shake_192s::PublicKey::try_from_bytes(&pk_bytes)
                    .map_err(|_e| SlhDsaError::InvalidPublicKey)?;
            }
            SecurityLevel::Shake256s => {
                let pk_bytes: [u8; shake_256s::PK_LEN] =
                    bytes.try_into().map_err(|_e| SlhDsaError::DeserializationError)?;
                shake_256s::PublicKey::try_from_bytes(&pk_bytes)
                    .map_err(|_e| SlhDsaError::InvalidPublicKey)?;
            }
        }

        Ok(VerifyingKey { security_level, bytes: key_bytes, len: expected_len })
    }

    /// Returns the security level
    #[must_use]
    pub fn security_level(&self) -> SecurityLevel {
        self.security_level
    }

    /// Returns the verifying key as bytes
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    /// Serializes the verifying key to bytes
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }

    /// Deserializes a verifying key from bytes
    ///
    /// # Errors
    /// Returns an error if the key length is incorrect or the key is malformed.
    pub fn from_bytes(security_level: SecurityLevel, bytes: &[u8]) -> Result<Self, SlhDsaError> {
        Self::new(security_level, bytes)
    }

    /// Verifies a signature on a message
    ///
    /// # Arguments
    ///
    /// * `message` - The message to verify
    /// * `signature` - The signature to verify
    /// * `context` - Optional context string (max 255 bytes, typically empty)
    ///
    /// # Returns
    ///
    /// Returns `Ok(true)` if the signature is valid, `Ok(false)` otherwise
    ///
    /// # Errors
    /// Returns an error if the context is too long (>255 bytes) or the key/signature is malformed.
    #[instrument(level = "debug", skip(self, message, signature, context), fields(security_level = ?self.security_level, message_len = message.len(), signature_len = signature.len()))]
    pub fn verify(
        &self,
        message: &[u8],
        signature: &[u8],
        context: Option<&[u8]>,
    ) -> Result<bool, SlhDsaError> {
        let ctx = context.unwrap_or(b"");

        // Validate context length
        if ctx.len() > 255 {
            return Err(SlhDsaError::ContextTooLong);
        }

        let is_valid = match self.security_level {
            SecurityLevel::Shake128s => {
                let pk_bytes: [u8; shake_128s::PK_LEN] =
                    self.as_bytes().try_into().map_err(|_e| SlhDsaError::InvalidPublicKey)?;
                let pk = shake_128s::PublicKey::try_from_bytes(&pk_bytes)
                    .map_err(|_e| SlhDsaError::InvalidPublicKey)?;
                let sig_bytes: [u8; shake_128s::SIG_LEN] =
                    signature.try_into().map_err(|_e| SlhDsaError::VerificationFailed)?;
                pk.verify(message, &sig_bytes, ctx)
            }
            SecurityLevel::Shake192s => {
                let pk_bytes: [u8; shake_192s::PK_LEN] =
                    self.as_bytes().try_into().map_err(|_e| SlhDsaError::InvalidPublicKey)?;
                let pk = shake_192s::PublicKey::try_from_bytes(&pk_bytes)
                    .map_err(|_e| SlhDsaError::InvalidPublicKey)?;
                let sig_bytes: [u8; shake_192s::SIG_LEN] =
                    signature.try_into().map_err(|_e| SlhDsaError::VerificationFailed)?;
                pk.verify(message, &sig_bytes, ctx)
            }
            SecurityLevel::Shake256s => {
                let pk_bytes: [u8; shake_256s::PK_LEN] =
                    self.as_bytes().try_into().map_err(|_e| SlhDsaError::InvalidPublicKey)?;
                let pk = shake_256s::PublicKey::try_from_bytes(&pk_bytes)
                    .map_err(|_e| SlhDsaError::InvalidPublicKey)?;
                let sig_bytes: [u8; shake_256s::SIG_LEN] =
                    signature.try_into().map_err(|_e| SlhDsaError::VerificationFailed)?;
                pk.verify(message, &sig_bytes, ctx)
            }
        };

        Ok(is_valid)
    }
}

// ============================================================================
// Signing Key (Secret Key)
// ============================================================================

/// SLH-DSA signing key (secret key)
///
/// This is a wrapper around the audited fips205 crate's private key.
/// Secret keys are zeroized on drop to prevent memory leaks.
///
/// # Security
///
/// - Does not implement `Clone` to prevent unzeroized copies
/// - Implements `ConstantTimeEq` for timing-safe comparisons
/// - Zeroized on drop via custom `Drop` implementation
pub struct SigningKey {
    /// The security level used
    security_level: SecurityLevel,

    /// The underlying secret key bytes (zeroized on drop)
    bytes: [u8; shake_256s::SK_LEN], // Max size for all variants

    /// The actual length of the secret key
    len: usize,

    /// The verifying key (public key)
    verifying_key: VerifyingKey,
}

impl ConstantTimeEq for SigningKey {
    fn ct_eq(&self, other: &Self) -> Choice {
        // Compare security level in constant time
        let level_eq = (self.security_level as u8).ct_eq(&(other.security_level as u8));
        // Compare length in constant time
        let len_eq = self.len.ct_eq(&other.len);
        // Compare bytes in constant time (only up to the actual length)
        let bytes_eq = self.bytes[..self.len].ct_eq(&other.bytes[..other.len]);
        level_eq & len_eq & bytes_eq
    }
}

impl PartialEq for SigningKey {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Eq for SigningKey {}

impl SigningKey {
    /// Generates a new signing key with the specified security level
    ///
    /// Uses the audited fips205 crate's `try_keygen()` function.
    /// After key generation, a FIPS 140-3 Pairwise Consistency Test (PCT)
    /// is performed to verify the keypair is valid.
    ///
    /// # Arguments
    ///
    /// * `security_level` - The security level to use
    ///
    /// # Returns
    ///
    /// Returns a tuple of (signing_key, verifying_key)
    ///
    /// # Errors
    ///
    /// Returns `SlhDsaError::RngError` if random number generation fails or PCT fails
    #[instrument(level = "debug", fields(security_level = ?security_level, nist_level = security_level.nist_level()))]
    pub fn generate(security_level: SecurityLevel) -> Result<(Self, VerifyingKey), SlhDsaError> {
        let (signing_key, verifying_key) = match security_level {
            SecurityLevel::Shake128s => {
                let (pk, sk) = shake_128s::try_keygen().map_err(|_e| SlhDsaError::RngError)?;
                let verifying_key = VerifyingKey {
                    security_level,
                    bytes: {
                        let mut b = [0u8; shake_256s::PK_LEN];
                        let pk_bytes = pk.into_bytes();
                        b[..pk_bytes.len()].copy_from_slice(&pk_bytes);
                        b
                    },
                    len: shake_128s::PK_LEN,
                };
                let signing_key = SigningKey {
                    security_level,
                    bytes: {
                        let mut b = [0u8; shake_256s::SK_LEN];
                        let sk_bytes = sk.into_bytes();
                        b[..sk_bytes.len()].copy_from_slice(&sk_bytes);
                        b
                    },
                    len: shake_128s::SK_LEN,
                    verifying_key: verifying_key.clone(),
                };
                (signing_key, verifying_key)
            }
            SecurityLevel::Shake192s => {
                let (pk, sk) = shake_192s::try_keygen().map_err(|_e| SlhDsaError::RngError)?;
                let verifying_key = VerifyingKey {
                    security_level,
                    bytes: {
                        let mut b = [0u8; shake_256s::PK_LEN];
                        let pk_bytes = pk.into_bytes();
                        b[..pk_bytes.len()].copy_from_slice(&pk_bytes);
                        b
                    },
                    len: shake_192s::PK_LEN,
                };
                let signing_key = SigningKey {
                    security_level,
                    bytes: {
                        let mut b = [0u8; shake_256s::SK_LEN];
                        let sk_bytes = sk.into_bytes();
                        b[..sk_bytes.len()].copy_from_slice(&sk_bytes);
                        b
                    },
                    len: shake_192s::SK_LEN,
                    verifying_key: verifying_key.clone(),
                };
                (signing_key, verifying_key)
            }
            SecurityLevel::Shake256s => {
                let (pk, sk) = shake_256s::try_keygen().map_err(|_e| SlhDsaError::RngError)?;
                let verifying_key = VerifyingKey {
                    security_level,
                    bytes: {
                        let mut b = [0u8; shake_256s::PK_LEN];
                        let pk_bytes = pk.into_bytes();
                        b[..pk_bytes.len()].copy_from_slice(&pk_bytes);
                        b
                    },
                    len: shake_256s::PK_LEN,
                };
                let signing_key = SigningKey {
                    security_level,
                    bytes: {
                        let mut b = [0u8; shake_256s::SK_LEN];
                        let sk_bytes = sk.into_bytes();
                        b[..sk_bytes.len()].copy_from_slice(&sk_bytes);
                        b
                    },
                    len: shake_256s::SK_LEN,
                    verifying_key: verifying_key.clone(),
                };
                (signing_key, verifying_key)
            }
        };

        // FIPS 140-3 Pairwise Consistency Test (PCT)
        // Sign and verify a test message to ensure the keypair is consistent
        crate::pct::pct_slh_dsa(&verifying_key, &signing_key)
            .map_err(|_e| SlhDsaError::RngError)?;

        Ok((signing_key, verifying_key))
    }

    /// Creates a new signing key from bytes
    ///
    /// # Errors
    /// Returns an error if the key length is incorrect or the key is malformed.
    pub fn new(security_level: SecurityLevel, bytes: &[u8]) -> Result<Self, SlhDsaError> {
        let expected_len = security_level.secret_key_size();
        if bytes.len() != expected_len {
            return Err(SlhDsaError::InvalidSecretKey);
        }

        let mut key_bytes = [0u8; shake_256s::SK_LEN];
        key_bytes[..expected_len].copy_from_slice(bytes);

        match security_level {
            SecurityLevel::Shake128s => {
                let sk_bytes: [u8; shake_128s::SK_LEN] =
                    bytes.try_into().map_err(|_e| SlhDsaError::DeserializationError)?;
                let sk = shake_128s::PrivateKey::try_from_bytes(&sk_bytes)
                    .map_err(|_e| SlhDsaError::InvalidSecretKey)?;
                let pk_bytes = sk.get_public_key().into_bytes();
                let verifying_key = VerifyingKey {
                    security_level,
                    bytes: {
                        let mut b = [0u8; shake_256s::PK_LEN];
                        b[..pk_bytes.len()].copy_from_slice(&pk_bytes);
                        b
                    },
                    len: shake_128s::PK_LEN,
                };
                Ok(SigningKey {
                    security_level,
                    bytes: key_bytes,
                    len: expected_len,
                    verifying_key,
                })
            }
            SecurityLevel::Shake192s => {
                let sk_bytes: [u8; shake_192s::SK_LEN] =
                    bytes.try_into().map_err(|_e| SlhDsaError::DeserializationError)?;
                let sk = shake_192s::PrivateKey::try_from_bytes(&sk_bytes)
                    .map_err(|_e| SlhDsaError::InvalidSecretKey)?;
                let pk_bytes = sk.get_public_key().into_bytes();
                let verifying_key = VerifyingKey {
                    security_level,
                    bytes: {
                        let mut b = [0u8; shake_256s::PK_LEN];
                        b[..pk_bytes.len()].copy_from_slice(&pk_bytes);
                        b
                    },
                    len: shake_192s::PK_LEN,
                };
                Ok(SigningKey {
                    security_level,
                    bytes: key_bytes,
                    len: expected_len,
                    verifying_key,
                })
            }
            SecurityLevel::Shake256s => {
                let sk_bytes: [u8; shake_256s::SK_LEN] =
                    bytes.try_into().map_err(|_e| SlhDsaError::DeserializationError)?;
                let sk = shake_256s::PrivateKey::try_from_bytes(&sk_bytes)
                    .map_err(|_e| SlhDsaError::InvalidSecretKey)?;
                let pk_bytes = sk.get_public_key().into_bytes();
                let verifying_key = VerifyingKey {
                    security_level,
                    bytes: {
                        let mut b = [0u8; shake_256s::PK_LEN];
                        b[..pk_bytes.len()].copy_from_slice(&pk_bytes);
                        b
                    },
                    len: shake_256s::PK_LEN,
                };
                Ok(SigningKey { security_level, bytes: sk_bytes, len: expected_len, verifying_key })
            }
        }
    }

    /// Returns the security level
    #[must_use]
    pub fn security_level(&self) -> SecurityLevel {
        self.security_level
    }

    /// Returns the signing key as bytes
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    /// Serializes the signing key to bytes
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }

    /// Deserializes a signing key from bytes
    ///
    /// # Errors
    /// Returns an error if the key length is incorrect or the key is malformed.
    pub fn from_bytes(security_level: SecurityLevel, bytes: &[u8]) -> Result<Self, SlhDsaError> {
        Self::new(security_level, bytes)
    }

    /// Returns the verifying key (public key) associated with this signing key
    #[must_use]
    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }

    /// Signs a message using this signing key
    ///
    /// Uses the audited fips205 crate's `try_sign()` function with hedging enabled
    /// for better security against side-channel attacks.
    ///
    /// # Arguments
    ///
    /// * `message` - The message to sign
    /// * `context` - Optional context string (max 255 bytes, typically empty)
    ///
    /// # Returns
    ///
    /// Returns the signature as a byte vector
    ///
    /// # Errors
    ///
    /// Returns `SlhDsaError::RngError` if random number generation fails
    #[instrument(level = "debug", skip(self, message, context), fields(security_level = ?self.security_level, message_len = message.len(), has_context = context.is_some()))]
    pub fn sign(&self, message: &[u8], context: Option<&[u8]>) -> Result<Vec<u8>, SlhDsaError> {
        let ctx = context.unwrap_or(b"");

        // Validate context length
        if ctx.len() > 255 {
            return Err(SlhDsaError::ContextTooLong);
        }

        match self.security_level {
            SecurityLevel::Shake128s => {
                let sk_bytes: [u8; shake_128s::SK_LEN] =
                    self.as_bytes().try_into().map_err(|_e| SlhDsaError::InvalidSecretKey)?;
                let sk = shake_128s::PrivateKey::try_from_bytes(&sk_bytes)
                    .map_err(|_e| SlhDsaError::InvalidSecretKey)?;
                let sig = sk.try_sign(message, ctx, true).map_err(|_e| SlhDsaError::RngError)?;
                Ok(sig.as_ref().to_vec())
            }
            SecurityLevel::Shake192s => {
                let sk_bytes: [u8; shake_192s::SK_LEN] =
                    self.as_bytes().try_into().map_err(|_e| SlhDsaError::InvalidSecretKey)?;
                let sk = shake_192s::PrivateKey::try_from_bytes(&sk_bytes)
                    .map_err(|_e| SlhDsaError::InvalidSecretKey)?;
                let sig = sk.try_sign(message, ctx, true).map_err(|_e| SlhDsaError::RngError)?;
                Ok(sig.as_ref().to_vec())
            }
            SecurityLevel::Shake256s => {
                let sk_bytes: [u8; shake_256s::SK_LEN] =
                    self.as_bytes().try_into().map_err(|_e| SlhDsaError::InvalidSecretKey)?;
                let sk = shake_256s::PrivateKey::try_from_bytes(&sk_bytes)
                    .map_err(|_e| SlhDsaError::InvalidSecretKey)?;
                let sig = sk.try_sign(message, ctx, true).map_err(|_e| SlhDsaError::RngError)?;
                Ok(sig.as_ref().to_vec())
            }
        }
    }

    /// Signs a message and returns the verifying key for convenience
    ///
    /// # Errors
    /// Returns an error if the context is too long or random number generation fails.
    pub fn sign_with_key(
        &self,
        message: &[u8],
        context: Option<&[u8]>,
    ) -> Result<(Vec<u8>, &VerifyingKey), SlhDsaError> {
        let signature = self.sign(message, context)?;
        Ok((signature, &self.verifying_key))
    }
}

// Zeroize the signing key on drop to prevent memory leaks
impl Drop for SigningKey {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

// Implement Zeroize for SigningKey to allow explicit zeroization
impl Zeroize for SigningKey {
    fn zeroize(&mut self) {
        self.bytes.zeroize();
    }
}

impl std::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigningKey")
            .field("security_level", &self.security_level)
            .field("verifying_key", &self.verifying_key)
            .finish_non_exhaustive()
    }
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::expect_used)] // Tests use expect for simplicity
#[allow(clippy::explicit_iter_loop)] // Tests use iterator style
#[allow(clippy::redundant_clone)] // Tests clone for independent modification
mod tests {
    use super::*;

    // Test 1: Key generation works for all security levels
    #[test]
    fn test_key_generation_all_levels() {
        for level in [SecurityLevel::Shake128s, SecurityLevel::Shake192s, SecurityLevel::Shake256s]
        {
            let (sk, pk) = SigningKey::generate(level).expect("Key generation failed");
            assert_eq!(sk.security_level(), level);
            assert_eq!(pk.security_level(), level);
            assert_eq!(
                pk.as_bytes().len(),
                level.public_key_size(),
                "Public key size mismatch for {:?}",
                level
            );
            assert_eq!(
                sk.as_bytes().len(),
                level.secret_key_size(),
                "Secret key size mismatch for {:?}",
                level
            );
        }
    }

    // Test 2: Sign and verify round-trip
    #[test]
    fn test_sign_verify_roundtrip() {
        for level in [SecurityLevel::Shake128s, SecurityLevel::Shake192s, SecurityLevel::Shake256s]
        {
            let (sk, pk) = SigningKey::generate(level).expect("Key generation failed");
            let message = b"Test message for SLH-DSA";
            let signature = sk.sign(message, None).expect("Signing failed");

            assert_eq!(
                signature.len(),
                level.signature_size(),
                "Signature size mismatch for {:?}",
                level
            );

            let is_valid = pk.verify(message, &signature, None).expect("Verification failed");
            assert!(is_valid, "Signature verification failed for {:?}", level);
        }
    }

    // Test 3: Verify rejects invalid signatures
    #[test]
    fn test_verify_invalid_signature() {
        let (sk, pk) =
            SigningKey::generate(SecurityLevel::Shake128s).expect("Key generation failed");
        let message = b"Test message";
        let mut signature = sk.sign(message, None).expect("Signing failed");

        // Corrupt the signature
        signature[0] ^= 0xFF;

        let is_valid = pk.verify(message, &signature, None).expect("Verification failed");
        assert!(!is_valid, "Verification should fail for corrupted signature");
    }

    // Test 4: Verify rejects wrong message
    #[test]
    fn test_verify_wrong_message() {
        let (sk, pk) =
            SigningKey::generate(SecurityLevel::Shake128s).expect("Key generation failed");
        let message = b"Test message";
        let wrong_message = b"Wrong message";
        let signature = sk.sign(message, None).expect("Signing failed");

        let is_valid = pk.verify(wrong_message, &signature, None).expect("Verification failed");
        assert!(!is_valid, "Verification should fail for wrong message");
    }

    // Test 5: Serialization and deserialization
    #[test]
    fn test_serialization() {
        for level in [SecurityLevel::Shake128s, SecurityLevel::Shake192s, SecurityLevel::Shake256s]
        {
            let (sk, pk) = SigningKey::generate(level).expect("Key generation failed");

            // Serialize and deserialize public key
            let pk_bytes = pk.to_bytes();
            let pk_restored = VerifyingKey::from_bytes(level, &pk_bytes)
                .expect("Public key deserialization failed");
            assert_eq!(pk, pk_restored);

            // Serialize and deserialize secret key
            let sk_bytes = sk.to_bytes();
            let sk_restored = SigningKey::from_bytes(level, &sk_bytes)
                .expect("Secret key deserialization failed");
            assert_eq!(sk.security_level(), sk_restored.security_level());
            assert_eq!(sk.as_bytes(), sk_restored.as_bytes());

            // Verify that restored key works
            let message = b"Test message";
            let signature = sk_restored.sign(message, None).expect("Signing failed");
            let is_valid =
                pk_restored.verify(message, &signature, None).expect("Verification failed");
            assert!(is_valid, "Signature verification failed after deserialization");
        }
    }

    // Test 6: Invalid key handling
    #[test]
    fn test_invalid_key_handling() {
        // Invalid public key (wrong size)
        let result = VerifyingKey::new(SecurityLevel::Shake128s, &[0u8; 16]);
        assert!(matches!(result, Err(SlhDsaError::InvalidPublicKey)));

        // Invalid secret key (wrong size)
        let result = SigningKey::new(SecurityLevel::Shake128s, &[0u8; 16]);
        assert!(matches!(result, Err(SlhDsaError::InvalidSecretKey)));
    }

    // Test 7: Context string handling
    #[test]
    fn test_context_string() {
        let (sk, pk) =
            SigningKey::generate(SecurityLevel::Shake128s).expect("Key generation failed");
        let message = b"Test message";
        let context = b"Test context";

        // Sign with context
        let signature = sk.sign(message, Some(context)).expect("Signing with context failed");

        // Verify with context
        let is_valid = pk.verify(message, &signature, Some(context)).expect("Verification failed");
        assert!(is_valid, "Signature verification failed with context");

        // Verify with wrong context should fail
        let is_valid =
            pk.verify(message, &signature, Some(b"Wrong context")).expect("Verification failed");
        assert!(!is_valid, "Verification should fail with wrong context");
    }

    // Test 8: Context string too long
    #[test]
    fn test_context_too_long() {
        let (sk, _) =
            SigningKey::generate(SecurityLevel::Shake128s).expect("Key generation failed");
        let message = b"Test message";
        let long_context = vec![0u8; 256]; // 256 bytes, max is 255

        let result = sk.sign(message, Some(&long_context));
        assert!(matches!(result, Err(SlhDsaError::ContextTooLong)));
    }

    // Test 9: Empty message signing
    #[test]
    fn test_empty_message() {
        let (sk, pk) =
            SigningKey::generate(SecurityLevel::Shake128s).expect("Key generation failed");
        let message = b"";

        let signature = sk.sign(message, None).expect("Signing empty message failed");
        let is_valid = pk.verify(message, &signature, None).expect("Verification failed");
        assert!(is_valid, "Signature verification failed for empty message");
    }

    // Test 10: Large message signing
    #[test]
    fn test_large_message() {
        let (sk, pk) =
            SigningKey::generate(SecurityLevel::Shake128s).expect("Key generation failed");
        let message = vec![0u8; 65536]; // 64 KB message

        let signature = sk.sign(&message, None).expect("Signing large message failed");
        let is_valid = pk.verify(&message, &signature, None).expect("Verification failed");
        assert!(is_valid, "Signature verification failed for large message");
    }

    // Test 11: Multiple signatures with same key
    #[test]
    fn test_multiple_signatures() {
        let (sk, pk) =
            SigningKey::generate(SecurityLevel::Shake128s).expect("Key generation failed");

        for i in 0..10 {
            let message = format!("Test message {}", i).as_bytes().to_vec();
            let signature = sk.sign(&message, None).expect("Signing failed");
            let is_valid = pk.verify(&message, &signature, None).expect("Verification failed");
            assert!(is_valid, "Signature verification failed for message {}", i);
        }
    }

    // Test 12: Security level constants
    #[test]
    fn test_security_level_constants() {
        // Check NIST levels
        assert_eq!(SecurityLevel::Shake128s.nist_level(), 1);
        assert_eq!(SecurityLevel::Shake192s.nist_level(), 3);
        assert_eq!(SecurityLevel::Shake256s.nist_level(), 5);

        // Check key and signature sizes
        assert_eq!(SecurityLevel::Shake128s.public_key_size(), shake_128s::PK_LEN);
        assert_eq!(SecurityLevel::Shake128s.secret_key_size(), shake_128s::SK_LEN);
        assert_eq!(SecurityLevel::Shake128s.signature_size(), shake_128s::SIG_LEN);

        assert_eq!(SecurityLevel::Shake192s.public_key_size(), shake_192s::PK_LEN);
        assert_eq!(SecurityLevel::Shake192s.secret_key_size(), shake_192s::SK_LEN);
        assert_eq!(SecurityLevel::Shake192s.signature_size(), shake_192s::SIG_LEN);

        assert_eq!(SecurityLevel::Shake256s.public_key_size(), shake_256s::PK_LEN);
        assert_eq!(SecurityLevel::Shake256s.secret_key_size(), shake_256s::SK_LEN);
        assert_eq!(SecurityLevel::Shake256s.signature_size(), shake_256s::SIG_LEN);
    }

    #[test]
    fn test_slh_dsa_secret_key_zeroization() {
        let (mut sk, _pk) =
            SigningKey::generate(SecurityLevel::Shake128s).expect("Key generation should succeed");

        let sk_bytes_before = sk.as_bytes().to_vec();
        assert!(
            !sk_bytes_before.iter().all(|&b| b == 0),
            "Secret key should contain non-zero data"
        );

        sk.zeroize();

        let sk_bytes_after = sk.as_bytes();
        assert!(sk_bytes_after.iter().all(|&b| b == 0), "Secret key should be zeroized");
    }

    #[test]
    fn test_slh_dsa_all_security_levels_zeroization() {
        let levels = [SecurityLevel::Shake128s, SecurityLevel::Shake192s, SecurityLevel::Shake256s];

        for level in levels.iter() {
            let (mut sk, _pk) =
                SigningKey::generate(*level).expect("Key generation should succeed");

            let sk_bytes_before = sk.as_bytes().to_vec();
            assert!(
                !sk_bytes_before.iter().all(|&b| b == 0),
                "Secret key for {:?} should contain non-zero data",
                level
            );

            sk.zeroize();

            let sk_bytes_after = sk.as_bytes();
            assert!(
                sk_bytes_after.iter().all(|&b| b == 0),
                "Secret key for {:?} should be zeroized",
                level
            );
        }
    }

    #[test]
    fn test_slh_dsa_signing_after_zeroization() {
        let (mut sk, pk) =
            SigningKey::generate(SecurityLevel::Shake128s).expect("Key generation should succeed");
        let message = b"Test message";

        let signature_before = sk.sign(message, None).expect("Signing should succeed");
        let is_valid_before =
            pk.verify(message, &signature_before, None).expect("Verification should succeed");
        assert!(is_valid_before, "Signature should be valid before zeroization");

        sk.zeroize();

        let result = sk.sign(message, None);
        assert!(result.is_err(), "Signing should fail after zeroization");
    }

    // Test 13: VerifyingKey::verify returns Result
    #[test]
    fn test_verify_returns_result() {
        let (sk, pk) =
            SigningKey::generate(SecurityLevel::Shake128s).expect("Key generation failed");
        let message = b"Test message";
        let signature = sk.sign(message, None).expect("Signing failed");

        // Valid signature should return Ok(true)
        let result = pk.verify(message, &signature, None);
        assert!(matches!(result, Ok(true)));

        // Invalid signature should return Ok(false), not Err
        let mut invalid_sig = signature.clone();
        invalid_sig[0] ^= 0xFF;
        let result = pk.verify(message, &invalid_sig, None);
        assert!(matches!(result, Ok(false)));
    }
}
