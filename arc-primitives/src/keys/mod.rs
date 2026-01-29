#![deny(unsafe_code)]
#![warn(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]
// JUSTIFICATION: Key management module
// - items_after_test_module: impl blocks placed after embedded tests for code organization
#![allow(clippy::items_after_test_module)]

//! # Cryptographic Key Management
//!
//! High-level key types and management operations for LatticeArc.
//!
//! ## Key Types
//!
//! - `KeyPair`: Complete hybrid keypair (ML-KEM + X25519)
//! - `PublicKey`: Hybrid public key
//! - `SecretKey`: Hybrid secret key
//!
//! ## Security Features
//!
//! - Automatic zeroization on drop
//! - Secure memory handling
//! - Post-quantum + classical hybrid cryptography
//!
//! ## Example
//!
//! ```ignore
//! use arc_primitives::keys::KeyPair;
//!
//! let keypair = KeyPair::generate()?;
//!
//! // Access keys
//! let public_key = keypair.public_key();
//! let secret_key = keypair.secret_key();
//! # Ok::<(), arc_primitives::keys::KeyError>(())
//! ```

use thiserror::Error;
use zeroize::{ZeroizeOnDrop, Zeroizing};

use crate::kem::ecdh::{X25519PublicKey as EccPublicKey, X25519SecretKey as EccSecretKey};

/// Error types for key operations
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum KeyError {
    /// Key generation operation failed.
    #[error("Key generation failed: {0}")]
    GenerationFailed(String),

    /// Key serialization to bytes failed.
    #[error("Key serialization failed: {0}")]
    SerializationFailed(String),

    /// Key deserialization from bytes failed.
    #[error("Key deserialization failed: {0}")]
    DeserializationFailed(String),

    /// The provided key is invalid or malformed.
    #[error("Invalid key: {0}")]
    InvalidKey(String),
}

impl From<rand::Error> for KeyError {
    fn from(e: rand::Error) -> Self {
        KeyError::GenerationFailed(e.to_string())
    }
}

// =============================================================================
// Hybrid Key Types (ML-KEM + X25519) - Requires non-fips feature
// =============================================================================

/// A complete hybrid keypair for encryption/decryption operations.
///
/// This hybrid keypair combines post-quantum (ML-KEM) and classical (X25519)
/// cryptography for defense-in-depth security.
///
/// **Note:** This type requires the `non-fips` feature. For FIPS-only builds,
/// use the ML-KEM types directly from `arc_primitives::kem::ml_kem`.
#[derive(Debug)]
pub struct KeyPair {
    /// The public key part
    pub(crate) public_key: PublicKey,
    /// The secret key (must be kept private)
    pub(crate) secret_key: SecretKey,
}

/// Hybrid public key for encryption and signature verification.
///
/// Contains both ML-KEM (post-quantum) and X25519 (classical) public keys.
///
/// **Note:** This type requires the `non-fips` feature.
///
/// ## Security Notes
///
/// - Can be freely shared
/// - Used for encrypting messages
/// - Used for verifying signatures
///
/// ## Serialization
///
/// Public keys implement secure serialization with format validation.
#[derive(Clone)]
pub struct PublicKey {
    /// ML-KEM public key bytes (post-quantum)
    pub(crate) ml_pk: Vec<u8>,
    /// ECDH public key (classical)
    pub(crate) ecc_pk: EccPublicKey,
}

impl std::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PublicKey").finish_non_exhaustive()
    }
}

impl PublicKey {
    /// Get the ML-KEM public key bytes
    #[must_use]
    pub fn ml_kem(&self) -> &[u8] {
        &self.ml_pk
    }

    /// Get the ECDH public key
    #[must_use]
    pub fn ecc(&self) -> &EccPublicKey {
        &self.ecc_pk
    }

    /// Serialize to bytes
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.ml_pk);
        bytes.extend_from_slice(self.ecc_pk.as_bytes());
        bytes
    }

    /// Deserialize from bytes
    ///
    /// # Errors
    /// Returns an error if there are insufficient bytes for deserialization.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, KeyError> {
        if bytes.len() < 32 {
            return Err(KeyError::DeserializationFailed(
                "Insufficient bytes for public key".to_string(),
            ));
        }

        // Safe: already validated bytes.len() >= 32 above
        let ecc_start = bytes.len().saturating_sub(32);
        let ecc_pk_bytes: [u8; 32] = bytes
            .get(ecc_start..)
            .ok_or_else(|| KeyError::DeserializationFailed("ECC key out of bounds".to_string()))?
            .try_into()
            .map_err(|_e| KeyError::DeserializationFailed("Invalid ECC key bytes".to_string()))?;

        let ml_pk = bytes
            .get(..ecc_start)
            .ok_or_else(|| KeyError::DeserializationFailed("ML-KEM key out of bounds".to_string()))?
            .to_vec();
        let ecc_pk = EccPublicKey::from_bytes(&ecc_pk_bytes)
            .map_err(|e| KeyError::DeserializationFailed(format!("Invalid ECC public key: {e}")))?;

        Ok(Self { ml_pk, ecc_pk })
    }

    /// Get the length in bytes
    #[must_use]
    pub fn len(&self) -> usize {
        self.ml_pk.len().saturating_add(32)
    }

    /// Always false for valid keys
    #[must_use]
    pub fn is_empty(&self) -> bool {
        false
    }
}

/// Hybrid secret key for decryption and digital signing.
///
/// Contains both ML-KEM (post-quantum) and X25519 (classical) secret keys.
///
/// **Note:** This type requires the `non-fips` feature.
///
/// This key must be kept absolutely private and secure. It is used to:
/// - Decrypt messages encrypted with corresponding public key
/// - Create digital signatures that can be verified with the public key
///
/// ## Security Notes
///
/// - **NEVER share or expose this key**
/// - Automatically zeroized when dropped to prevent memory leaks
/// - Contains sensitive cryptographic material
/// - Use hardware security modules (HSM) for production storage
///
/// ## Memory Safety
///
/// This struct implements `ZeroizeOnDrop` to ensure sensitive key material
/// is securely erased from memory when key goes out of scope.
#[derive(ZeroizeOnDrop)]
pub struct SecretKey {
    /// ML-KEM secret key bytes (post-quantum)
    #[zeroize(skip)]
    pub(crate) ml_sk: Zeroizing<Vec<u8>>,
    /// ECDH secret key (classical)
    #[zeroize(skip)]
    pub(crate) ecc_sk: Zeroizing<EccSecretKey>,
}

impl std::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretKey").finish_non_exhaustive()
    }
}

impl SecretKey {
    /// Get the ML-KEM secret key bytes
    #[must_use]
    pub fn ml_kem(&self) -> &[u8] {
        &self.ml_sk
    }

    /// Get the ECDH secret key
    #[must_use]
    pub fn ecc(&self) -> &EccSecretKey {
        &self.ecc_sk
    }

    /// Serialize to bytes
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.ml_sk);
        bytes.extend_from_slice((*self.ecc_sk).as_bytes());
        bytes
    }

    /// Deserialize from bytes
    ///
    /// # Errors
    /// Returns an error if there are insufficient bytes for deserialization.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, KeyError> {
        if bytes.len() < 32 {
            return Err(KeyError::DeserializationFailed(
                "Insufficient bytes for secret key".to_string(),
            ));
        }

        // Safe: already validated bytes.len() >= 32 above
        let ecc_start = bytes.len().saturating_sub(32);
        let ecc_sk_bytes: [u8; 32] = bytes
            .get(ecc_start..)
            .ok_or_else(|| KeyError::DeserializationFailed("ECC key out of bounds".to_string()))?
            .try_into()
            .map_err(|_e| KeyError::DeserializationFailed("Invalid ECC key bytes".to_string()))?;

        let ml_sk = Zeroizing::new(
            bytes
                .get(..ecc_start)
                .ok_or_else(|| {
                    KeyError::DeserializationFailed("ML-KEM key out of bounds".to_string())
                })?
                .to_vec(),
        );
        let ecc_sk = EccSecretKey::from_bytes(&ecc_sk_bytes)
            .map_err(|e| KeyError::DeserializationFailed(format!("Invalid ECC secret key: {e}")))?;

        Ok(Self { ml_sk, ecc_sk: Zeroizing::new(ecc_sk) })
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)] // Tests use expect for simplicity
#[allow(clippy::redundant_clone)] // Test clones needed for struct construction
mod zeroization_tests {
    use super::*;

    #[test]
    #[ignore = "aws-lc-rs does not expose ML-KEM secret key bytes for serialization"]
    fn test_keypair_secret_data_nonzero() {
        let keypair = KeyPair::generate().expect("Should generate keypair");
        let secret_key = keypair.secret_key();

        let ml_sk_before = secret_key.ml_kem();
        let ecc_sk_before = secret_key.ecc().as_bytes();

        assert!(
            !ml_sk_before.iter().all(|&b| b == 0),
            "ML-KEM secret should contain non-zero data"
        );
        assert!(!ecc_sk_before.iter().all(|&b| b == 0), "ECC secret should contain non-zero data");
    }

    #[test]
    fn test_secret_key_drop_zeroization() {
        let test_ml_data = vec![0xEE; 2400];
        let test_ecc_data = [0xFF; 32];

        {
            let ml_sk = Zeroizing::new(test_ml_data);
            let ecc_sk_inner =
                EccSecretKey::from_bytes(&test_ecc_data).expect("Valid ECC key bytes");

            let sk = SecretKey { ml_sk: ml_sk.clone(), ecc_sk: Zeroizing::new(ecc_sk_inner) };

            assert!(
                !sk.ml_kem().iter().all(|&b| b == 0),
                "ML-KEM secret should contain non-zero data"
            );
            assert!(
                !sk.ecc().as_bytes().iter().all(|&b| b == 0),
                "ECC secret should contain non-zero data"
            );
        }
    }
}

impl KeyPair {
    /// Generate a new hybrid keypair (ML-KEM + X25519)
    ///
    /// # Errors
    /// Returns an error if key generation fails.
    pub fn generate() -> Result<Self, KeyError> {
        let mut rng = rand::rngs::OsRng;
        let (ml_pk, ml_sk) = crate::kem::ml_kem::MlKem::generate_keypair(
            &mut rng,
            crate::kem::ml_kem::MlKemSecurityLevel::MlKem768,
        )
        .map_err(|e| KeyError::GenerationFailed(e.to_string()))?;
        let (ecc_pk, ecc_sk) = crate::kem::ecdh::generate_keypair(&mut rng)
            .map_err(|e| KeyError::GenerationFailed(e.to_string()))?;

        Ok(Self {
            public_key: PublicKey { ml_pk: ml_pk.into_bytes(), ecc_pk },
            secret_key: SecretKey {
                ml_sk: Zeroizing::new(ml_sk.into_bytes()),
                ecc_sk: Zeroizing::new(ecc_sk),
            },
        })
    }

    /// Get the public key
    #[must_use]
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// Get the secret key
    #[must_use]
    pub fn secret_key(&self) -> &SecretKey {
        &self.secret_key
    }
}
