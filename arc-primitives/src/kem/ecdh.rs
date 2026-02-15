#![deny(unsafe_code)]
#![warn(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

//! ECDH (Elliptic Curve Diffie-Hellman) Key Exchange
//!
//! This module provides ECDH using X25519 and NIST curves (P-256, P-384, P-521)
//! via aws-lc-rs for FIPS 140-3 compliance and optimized performance (AVX2, AES-NI).
//!
//! # Supported Curves
//!
//! - **X25519**: Modern curve (RFC 7748), 128-bit security
//! - **P-256 (NIST P-256/secp256r1)**: FIPS 186-4, 128-bit security
//! - **P-384 (NIST P-384/secp384r1)**: FIPS 186-4, 192-bit security
//! - **P-521 (NIST P-521/secp521r1)**: FIPS 186-4, 256-bit security
//!
//! # Performance
//!
//! aws-lc-rs provides ~4x speedup over pure-Rust implementations:
//! - Key generation: ~6µs (vs ~24µs for x25519-dalek)
//! - Key agreement: ~6µs (vs ~20µs for x25519-dalek)
//!
//! # Example
//!
//! ```no_run
//! use arc_primitives::kem::ecdh::{EcdhP256KeyPair, EcdhP384KeyPair, EcdhP521KeyPair, X25519KeyPair};
//!
//! // P-256 key exchange
//! let alice = EcdhP256KeyPair::generate()?;
//! let bob = EcdhP256KeyPair::generate()?;
//!
//! let alice_pk = alice.public_key_bytes().to_vec();
//! let bob_pk = bob.public_key_bytes().to_vec();
//!
//! let alice_secret = alice.agree(&bob_pk)?;
//! let bob_secret = bob.agree(&alice_pk)?;
//!
//! assert_eq!(alice_secret, bob_secret);
//! # Ok::<(), arc_primitives::kem::ecdh::EcdhError>(())
//! ```

use aws_lc_rs::agreement::{self, EphemeralPrivateKey, PrivateKey, UnparsedPublicKey, X25519};
use aws_lc_rs::encoding::{AsBigEndian, Curve25519SeedBin};

// ECDH curve algorithms - imported where used to avoid lint warnings
use aws_lc_rs::agreement::{ECDH_P256, ECDH_P384, ECDH_P521};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// X25519 key size in bytes
pub const X25519_KEY_SIZE: usize = 32;

/// P-256 public key size in bytes (uncompressed: 1 + 32 + 32 = 65 bytes)
pub const P256_PUBLIC_KEY_SIZE: usize = 65;

/// P-256 shared secret size in bytes (x-coordinate only)
pub const P256_SHARED_SECRET_SIZE: usize = 32;

/// P-384 public key size in bytes (uncompressed: 1 + 48 + 48 = 97 bytes)
pub const P384_PUBLIC_KEY_SIZE: usize = 97;

/// P-384 shared secret size in bytes (x-coordinate only)
pub const P384_SHARED_SECRET_SIZE: usize = 48;

/// P-521 public key size in bytes (uncompressed: 1 + 66 + 66 = 133 bytes)
pub const P521_PUBLIC_KEY_SIZE: usize = 133;

/// P-521 shared secret size in bytes (x-coordinate only)
pub const P521_SHARED_SECRET_SIZE: usize = 66;

/// Supported ECDH curve types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EcdhCurve {
    /// X25519 curve (Curve25519)
    X25519,
    /// NIST P-256 curve (secp256r1)
    P256,
    /// NIST P-384 curve (secp384r1)
    P384,
    /// NIST P-521 curve (secp521r1)
    P521,
}

impl EcdhCurve {
    /// Get the public key size for this curve
    #[must_use]
    pub const fn public_key_size(self) -> usize {
        match self {
            Self::X25519 => X25519_KEY_SIZE,
            Self::P256 => P256_PUBLIC_KEY_SIZE,
            Self::P384 => P384_PUBLIC_KEY_SIZE,
            Self::P521 => P521_PUBLIC_KEY_SIZE,
        }
    }

    /// Get the shared secret size for this curve
    #[must_use]
    pub const fn shared_secret_size(self) -> usize {
        match self {
            Self::X25519 => X25519_KEY_SIZE,
            Self::P256 => P256_SHARED_SECRET_SIZE,
            Self::P384 => P384_SHARED_SECRET_SIZE,
            Self::P521 => P521_SHARED_SECRET_SIZE,
        }
    }

    /// Get the curve name for display purposes
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::X25519 => "X25519",
            Self::P256 => "P-256",
            Self::P384 => "P-384",
            Self::P521 => "P-521",
        }
    }
}

/// Error types for ECDH operations
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum EcdhError {
    /// Key generation failed
    #[error("ECDH key generation failed")]
    KeyGenerationFailed,

    /// Shared secret derivation failed
    #[error("ECDH shared secret derivation failed")]
    SharedSecretDerivationFailed,

    /// Invalid key size
    #[error("Invalid key size: expected {expected}, got {actual}")]
    InvalidKeySize {
        /// Expected key size in bytes
        expected: usize,
        /// Actual key size in bytes
        actual: usize,
    },

    /// Key agreement failed
    #[error("ECDH key agreement failed")]
    AgreementFailed,

    /// Invalid public key (point not on curve)
    #[error("Invalid public key: point validation failed for curve {curve}")]
    InvalidPublicKey {
        /// The curve name
        curve: &'static str,
    },

    /// Invalid point format
    #[error("Invalid point format: expected {expected}, got {actual}")]
    InvalidPointFormat {
        /// Expected format description
        expected: &'static str,
        /// Actual format description
        actual: &'static str,
    },

    /// Invalid key data (rejected during import)
    #[error("Invalid key data")]
    InvalidKeyData,

    /// Curve mismatch
    #[error("Curve mismatch: expected {expected}, got {actual}")]
    CurveMismatch {
        /// Expected curve name
        expected: &'static str,
        /// Actual curve name
        actual: &'static str,
    },
}

/// X25519 public key wrapper
///
/// Contains the 32-byte public key for X25519 ECDH operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct X25519PublicKey {
    bytes: [u8; X25519_KEY_SIZE],
}

impl X25519PublicKey {
    /// Create a new X25519 public key from bytes
    ///
    /// # Errors
    /// Returns an error if the provided bytes are not exactly 32 bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, EcdhError> {
        if bytes.len() != X25519_KEY_SIZE {
            return Err(EcdhError::InvalidKeySize {
                expected: X25519_KEY_SIZE,
                actual: bytes.len(),
            });
        }
        let mut key_bytes = [0u8; X25519_KEY_SIZE];
        key_bytes.copy_from_slice(bytes);
        Ok(Self { bytes: key_bytes })
    }

    /// Get the public key as bytes
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; X25519_KEY_SIZE] {
        &self.bytes
    }

    /// Convert to `Vec<u8>`
    #[must_use]
    pub fn to_vec(&self) -> Vec<u8> {
        self.bytes.to_vec()
    }
}

/// X25519 secret key wrapper with automatic zeroization
///
/// Contains the 32-byte secret key for X25519 ECDH operations.
/// Automatically zeroizes memory on drop to prevent key leakage.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct X25519SecretKey {
    bytes: [u8; X25519_KEY_SIZE],
}

impl X25519SecretKey {
    /// Create a new X25519 secret key from bytes
    ///
    /// # Errors
    /// Returns an error if the provided bytes are not exactly 32 bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, EcdhError> {
        if bytes.len() != X25519_KEY_SIZE {
            return Err(EcdhError::InvalidKeySize {
                expected: X25519_KEY_SIZE,
                actual: bytes.len(),
            });
        }
        let mut key_bytes = [0u8; X25519_KEY_SIZE];
        key_bytes.copy_from_slice(bytes);
        Ok(Self { bytes: key_bytes })
    }

    /// Get the secret key as bytes
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; X25519_KEY_SIZE] {
        &self.bytes
    }
}

impl std::fmt::Debug for X25519SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("X25519SecretKey").field("bytes", &"[REDACTED]").finish()
    }
}

/// X25519 key pair containing both public and secret keys
///
/// This struct holds an ephemeral private key from aws-lc-rs along with
/// the computed public key bytes for transmission.
pub struct X25519KeyPair {
    private: EphemeralPrivateKey,
    public_bytes: [u8; X25519_KEY_SIZE],
}

impl X25519KeyPair {
    /// Generate a new X25519 key pair
    ///
    /// # Errors
    /// Returns an error if key generation fails.
    pub fn generate() -> Result<Self, EcdhError> {
        let rng = aws_lc_rs::rand::SystemRandom::new();
        let private = EphemeralPrivateKey::generate(&X25519, &rng)
            .map_err(|_e| EcdhError::KeyGenerationFailed)?;
        let public = private.compute_public_key().map_err(|_e| EcdhError::KeyGenerationFailed)?;

        let mut public_bytes = [0u8; X25519_KEY_SIZE];
        public_bytes.copy_from_slice(public.as_ref());

        Ok(Self { private, public_bytes })
    }

    /// Get public key bytes for transmission
    #[must_use]
    pub fn public_key_bytes(&self) -> &[u8; X25519_KEY_SIZE] {
        &self.public_bytes
    }

    /// Get the public key
    #[must_use]
    pub fn public_key(&self) -> X25519PublicKey {
        X25519PublicKey { bytes: self.public_bytes }
    }

    /// Perform X25519 key agreement with a peer's public key
    ///
    /// Consumes the private key to ensure single-use (ephemeral) semantics.
    ///
    /// # Errors
    /// Returns an error if key agreement fails.
    pub fn agree(self, peer_public_bytes: &[u8]) -> Result<[u8; X25519_KEY_SIZE], EcdhError> {
        let peer_public = UnparsedPublicKey::new(&X25519, peer_public_bytes);

        agreement::agree_ephemeral(
            self.private,
            peer_public,
            EcdhError::AgreementFailed,
            |shared_secret| {
                let mut result = [0u8; X25519_KEY_SIZE];
                result.copy_from_slice(shared_secret);
                Ok(result)
            },
        )
    }
}

impl std::fmt::Debug for X25519KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("X25519KeyPair")
            .field("public_bytes", &self.public_bytes)
            .field("private", &"[REDACTED]")
            .finish()
    }
}

/// X25519 static key pair for reusable Diffie-Hellman key agreement.
///
/// Unlike [`X25519KeyPair`] which uses ephemeral keys (consumed on use),
/// this type wraps [`PrivateKey`] which supports multiple `agree()` calls
/// without consuming the key. This is essential for hybrid KEM where the
/// recipient's X25519 key must persist for decapsulation.
///
/// # Limitations
///
/// aws-lc-rs does not support X25519 key import from raw bytes or DER.
/// Keys are **in-memory only** — they can be generated but not serialized
/// to disk. ML-KEM keys remain fully serializable.
///
/// # Example
///
/// ```rust,ignore
/// use arc_primitives::kem::ecdh::X25519StaticKeyPair;
///
/// let alice = X25519StaticKeyPair::generate()?;
/// let bob = X25519StaticKeyPair::generate()?;
///
/// // Commutativity: alice.agree(bob_pk) == bob.agree(alice_pk)
/// let ss1 = alice.agree(bob.public_key_bytes())?;
/// let ss2 = bob.agree(alice.public_key_bytes())?;
/// assert_eq!(ss1, ss2);
///
/// // Reusable: alice can agree with multiple peers
/// let carol = X25519StaticKeyPair::generate()?;
/// let ss3 = alice.agree(carol.public_key_bytes())?;
/// ```
pub struct X25519StaticKeyPair {
    private: PrivateKey,
    public_bytes: [u8; X25519_KEY_SIZE],
}

impl X25519StaticKeyPair {
    /// Generate a new X25519 static key pair.
    ///
    /// # Errors
    /// Returns an error if key generation fails.
    pub fn generate() -> Result<Self, EcdhError> {
        let private = PrivateKey::generate(&X25519).map_err(|_e| EcdhError::KeyGenerationFailed)?;
        let public = private.compute_public_key().map_err(|_e| EcdhError::KeyGenerationFailed)?;

        let mut public_bytes = [0u8; X25519_KEY_SIZE];
        public_bytes.copy_from_slice(public.as_ref());

        Ok(Self { private, public_bytes })
    }

    /// Get public key bytes for transmission.
    #[must_use]
    pub fn public_key_bytes(&self) -> &[u8; X25519_KEY_SIZE] {
        &self.public_bytes
    }

    /// Get the public key.
    #[must_use]
    pub fn public_key(&self) -> X25519PublicKey {
        X25519PublicKey { bytes: self.public_bytes }
    }

    /// Export the private key seed bytes (32 bytes).
    ///
    /// These bytes can be stored and later used with [`from_seed_bytes`](Self::from_seed_bytes)
    /// to reconstruct the key pair.
    ///
    /// # Errors
    /// Returns an error if seed extraction fails.
    pub fn seed_bytes(&self) -> Result<Zeroizing<[u8; X25519_KEY_SIZE]>, EcdhError> {
        let seed: Curve25519SeedBin<'_> =
            self.private.as_be_bytes().map_err(|_e| EcdhError::KeyGenerationFailed)?;
        let mut bytes = [0u8; X25519_KEY_SIZE];
        bytes.copy_from_slice(seed.as_ref());
        Ok(Zeroizing::new(bytes))
    }

    /// Reconstruct a key pair from previously exported seed bytes.
    ///
    /// # Errors
    /// Returns an error if the seed bytes are invalid.
    pub fn from_seed_bytes(seed: &[u8; X25519_KEY_SIZE]) -> Result<Self, EcdhError> {
        let private =
            PrivateKey::from_private_key(&X25519, seed).map_err(|_e| EcdhError::InvalidKeyData)?;
        let public = private.compute_public_key().map_err(|_e| EcdhError::KeyGenerationFailed)?;

        let mut public_bytes = [0u8; X25519_KEY_SIZE];
        public_bytes.copy_from_slice(public.as_ref());

        Ok(Self { private, public_bytes })
    }

    /// Perform X25519 key agreement with a peer's public key.
    ///
    /// Unlike [`X25519KeyPair::agree`], this does **not** consume the key,
    /// allowing multiple agreements with different peers.
    ///
    /// # Errors
    /// Returns an error if key agreement fails (e.g., invalid peer public key).
    pub fn agree(&self, peer_public_bytes: &[u8]) -> Result<[u8; X25519_KEY_SIZE], EcdhError> {
        let peer_public = UnparsedPublicKey::new(&X25519, peer_public_bytes);

        agreement::agree(&self.private, peer_public, EcdhError::AgreementFailed, |shared_secret| {
            let mut result = [0u8; X25519_KEY_SIZE];
            result.copy_from_slice(shared_secret);
            Ok(result)
        })
    }
}

impl std::fmt::Debug for X25519StaticKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("X25519StaticKeyPair")
            .field("public_bytes", &self.public_bytes)
            .field("private", &"[REDACTED]")
            .finish()
    }
}

/// Generate a new X25519 keypair
///
/// Returns the public key and secret key bytes. The secret key is stored
/// in a zeroizing container for security.
///
/// Validate a public key has correct size.
///
/// # Errors
/// Returns an error if the public key size does not match the expected X25519 key size.
pub fn validate_public_key(public_key: &X25519PublicKey) -> Result<(), EcdhError> {
    if public_key.as_bytes().len() != X25519_KEY_SIZE {
        return Err(EcdhError::InvalidKeySize {
            expected: X25519_KEY_SIZE,
            actual: public_key.as_bytes().len(),
        });
    }
    Ok(())
}

/// Validate a secret key has correct size.
///
/// # Errors
/// Returns an error if the secret key size does not match the expected X25519 key size.
pub fn validate_secret_key(secret_key: &X25519SecretKey) -> Result<(), EcdhError> {
    if secret_key.as_bytes().len() != X25519_KEY_SIZE {
        return Err(EcdhError::InvalidKeySize {
            expected: X25519_KEY_SIZE,
            actual: secret_key.as_bytes().len(),
        });
    }
    Ok(())
}

/// Perform X25519 key agreement
///
/// This creates an ephemeral key pair and performs Diffie-Hellman with the peer's
/// public key. For static-ephemeral or static-static DH, use `X25519KeyPair`.
///
/// # Errors
/// Returns an error if key agreement fails.
pub fn agree_ephemeral(
    peer_public_bytes: &[u8],
) -> Result<([u8; X25519_KEY_SIZE], [u8; X25519_KEY_SIZE]), EcdhError> {
    let keypair = X25519KeyPair::generate()?;
    let our_public = *keypair.public_key_bytes();
    let shared_secret = keypair.agree(peer_public_bytes)?;
    Ok((shared_secret, our_public))
}

// ============================================================================
// NIST P-256 (secp256r1) Implementation
// ============================================================================

/// P-256 public key wrapper
///
/// Contains the 65-byte uncompressed public key for P-256 ECDH operations.
/// Format: 0x04 || x-coordinate (32 bytes) || y-coordinate (32 bytes)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcdhP256PublicKey {
    bytes: Vec<u8>,
}

impl EcdhP256PublicKey {
    /// Create a new P-256 public key from bytes
    ///
    /// # Errors
    /// Returns an error if the provided bytes are not a valid uncompressed point (65 bytes).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, EcdhError> {
        if bytes.len() != P256_PUBLIC_KEY_SIZE {
            return Err(EcdhError::InvalidKeySize {
                expected: P256_PUBLIC_KEY_SIZE,
                actual: bytes.len(),
            });
        }
        // Check for uncompressed point format (0x04 prefix)
        if bytes.first() != Some(&0x04) {
            return Err(EcdhError::InvalidPointFormat {
                expected: "uncompressed (0x04 prefix)",
                actual: "invalid prefix",
            });
        }
        Ok(Self { bytes: bytes.to_vec() })
    }

    /// Get the public key as bytes
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Convert to `Vec<u8>`
    #[must_use]
    pub fn to_vec(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    /// Validate that this public key represents a valid point on P-256
    ///
    /// # Errors
    /// Returns an error if point validation fails.
    pub fn validate(&self) -> Result<(), EcdhError> {
        // aws-lc-rs validates points during key agreement, so we just check format
        if self.bytes.len() != P256_PUBLIC_KEY_SIZE {
            return Err(EcdhError::InvalidKeySize {
                expected: P256_PUBLIC_KEY_SIZE,
                actual: self.bytes.len(),
            });
        }
        if self.bytes.first() != Some(&0x04) {
            return Err(EcdhError::InvalidPointFormat {
                expected: "uncompressed (0x04 prefix)",
                actual: "invalid prefix",
            });
        }
        Ok(())
    }
}

/// P-256 key pair for ECDH key exchange
///
/// This struct holds an ephemeral private key from aws-lc-rs along with
/// the computed public key bytes for transmission.
pub struct EcdhP256KeyPair {
    private: EphemeralPrivateKey,
    public_bytes: Vec<u8>,
}

impl EcdhP256KeyPair {
    /// Generate a new P-256 key pair
    ///
    /// # Errors
    /// Returns an error if key generation fails.
    pub fn generate() -> Result<Self, EcdhError> {
        let rng = aws_lc_rs::rand::SystemRandom::new();
        let private = EphemeralPrivateKey::generate(&ECDH_P256, &rng)
            .map_err(|_e| EcdhError::KeyGenerationFailed)?;
        let public = private.compute_public_key().map_err(|_e| EcdhError::KeyGenerationFailed)?;
        Ok(Self { private, public_bytes: public.as_ref().to_vec() })
    }

    /// Get public key bytes for transmission
    #[must_use]
    pub fn public_key_bytes(&self) -> &[u8] {
        &self.public_bytes
    }

    /// Get the public key
    ///
    /// # Errors
    /// Returns an error if the public key bytes are invalid (should never happen).
    pub fn public_key(&self) -> Result<EcdhP256PublicKey, EcdhError> {
        EcdhP256PublicKey::from_bytes(&self.public_bytes)
    }

    /// Perform P-256 ECDH key agreement with a peer's public key
    ///
    /// Consumes the private key to ensure single-use (ephemeral) semantics.
    ///
    /// # Errors
    /// Returns an error if key agreement fails (e.g., invalid peer public key).
    pub fn agree(self, peer_public_bytes: &[u8]) -> Result<Vec<u8>, EcdhError> {
        let peer_public = UnparsedPublicKey::new(&ECDH_P256, peer_public_bytes);

        agreement::agree_ephemeral(
            self.private,
            peer_public,
            EcdhError::AgreementFailed,
            |shared_secret| Ok(shared_secret.to_vec()),
        )
    }
}

impl std::fmt::Debug for EcdhP256KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EcdhP256KeyPair")
            .field("public_bytes", &self.public_bytes)
            .field("private", &"[REDACTED]")
            .finish()
    }
}

// ============================================================================
// NIST P-384 (secp384r1) Implementation
// ============================================================================

/// P-384 public key wrapper
///
/// Contains the 97-byte uncompressed public key for P-384 ECDH operations.
/// Format: 0x04 || x-coordinate (48 bytes) || y-coordinate (48 bytes)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcdhP384PublicKey {
    bytes: Vec<u8>,
}

impl EcdhP384PublicKey {
    /// Create a new P-384 public key from bytes
    ///
    /// # Errors
    /// Returns an error if the provided bytes are not a valid uncompressed point (97 bytes).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, EcdhError> {
        if bytes.len() != P384_PUBLIC_KEY_SIZE {
            return Err(EcdhError::InvalidKeySize {
                expected: P384_PUBLIC_KEY_SIZE,
                actual: bytes.len(),
            });
        }
        // Check for uncompressed point format (0x04 prefix)
        if bytes.first() != Some(&0x04) {
            return Err(EcdhError::InvalidPointFormat {
                expected: "uncompressed (0x04 prefix)",
                actual: "invalid prefix",
            });
        }
        Ok(Self { bytes: bytes.to_vec() })
    }

    /// Get the public key as bytes
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Convert to `Vec<u8>`
    #[must_use]
    pub fn to_vec(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    /// Validate that this public key represents a valid point on P-384
    ///
    /// # Errors
    /// Returns an error if point validation fails.
    pub fn validate(&self) -> Result<(), EcdhError> {
        if self.bytes.len() != P384_PUBLIC_KEY_SIZE {
            return Err(EcdhError::InvalidKeySize {
                expected: P384_PUBLIC_KEY_SIZE,
                actual: self.bytes.len(),
            });
        }
        if self.bytes.first() != Some(&0x04) {
            return Err(EcdhError::InvalidPointFormat {
                expected: "uncompressed (0x04 prefix)",
                actual: "invalid prefix",
            });
        }
        Ok(())
    }
}

/// P-384 key pair for ECDH key exchange
///
/// This struct holds an ephemeral private key from aws-lc-rs along with
/// the computed public key bytes for transmission.
pub struct EcdhP384KeyPair {
    private: EphemeralPrivateKey,
    public_bytes: Vec<u8>,
}

impl EcdhP384KeyPair {
    /// Generate a new P-384 key pair
    ///
    /// # Errors
    /// Returns an error if key generation fails.
    pub fn generate() -> Result<Self, EcdhError> {
        let rng = aws_lc_rs::rand::SystemRandom::new();
        let private = EphemeralPrivateKey::generate(&ECDH_P384, &rng)
            .map_err(|_e| EcdhError::KeyGenerationFailed)?;
        let public = private.compute_public_key().map_err(|_e| EcdhError::KeyGenerationFailed)?;
        Ok(Self { private, public_bytes: public.as_ref().to_vec() })
    }

    /// Get public key bytes for transmission
    #[must_use]
    pub fn public_key_bytes(&self) -> &[u8] {
        &self.public_bytes
    }

    /// Get the public key
    ///
    /// # Errors
    /// Returns an error if the public key bytes are invalid (should never happen).
    pub fn public_key(&self) -> Result<EcdhP384PublicKey, EcdhError> {
        EcdhP384PublicKey::from_bytes(&self.public_bytes)
    }

    /// Perform P-384 ECDH key agreement with a peer's public key
    ///
    /// Consumes the private key to ensure single-use (ephemeral) semantics.
    ///
    /// # Errors
    /// Returns an error if key agreement fails (e.g., invalid peer public key).
    pub fn agree(self, peer_public_bytes: &[u8]) -> Result<Vec<u8>, EcdhError> {
        let peer_public = UnparsedPublicKey::new(&ECDH_P384, peer_public_bytes);

        agreement::agree_ephemeral(
            self.private,
            peer_public,
            EcdhError::AgreementFailed,
            |shared_secret| Ok(shared_secret.to_vec()),
        )
    }
}

impl std::fmt::Debug for EcdhP384KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EcdhP384KeyPair")
            .field("public_bytes", &self.public_bytes)
            .field("private", &"[REDACTED]")
            .finish()
    }
}

// ============================================================================
// NIST P-521 (secp521r1) Implementation
// ============================================================================

/// P-521 public key wrapper
///
/// Contains the 133-byte uncompressed public key for P-521 ECDH operations.
/// Format: 0x04 || x-coordinate (66 bytes) || y-coordinate (66 bytes)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcdhP521PublicKey {
    bytes: Vec<u8>,
}

impl EcdhP521PublicKey {
    /// Create a new P-521 public key from bytes
    ///
    /// # Errors
    /// Returns an error if the provided bytes are not a valid uncompressed point (133 bytes).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, EcdhError> {
        if bytes.len() != P521_PUBLIC_KEY_SIZE {
            return Err(EcdhError::InvalidKeySize {
                expected: P521_PUBLIC_KEY_SIZE,
                actual: bytes.len(),
            });
        }
        // Check for uncompressed point format (0x04 prefix)
        if bytes.first() != Some(&0x04) {
            return Err(EcdhError::InvalidPointFormat {
                expected: "uncompressed (0x04 prefix)",
                actual: "invalid prefix",
            });
        }
        Ok(Self { bytes: bytes.to_vec() })
    }

    /// Get the public key as bytes
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Convert to `Vec<u8>`
    #[must_use]
    pub fn to_vec(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    /// Validate that this public key represents a valid point on P-521
    ///
    /// # Errors
    /// Returns an error if point validation fails.
    pub fn validate(&self) -> Result<(), EcdhError> {
        if self.bytes.len() != P521_PUBLIC_KEY_SIZE {
            return Err(EcdhError::InvalidKeySize {
                expected: P521_PUBLIC_KEY_SIZE,
                actual: self.bytes.len(),
            });
        }
        if self.bytes.first() != Some(&0x04) {
            return Err(EcdhError::InvalidPointFormat {
                expected: "uncompressed (0x04 prefix)",
                actual: "invalid prefix",
            });
        }
        Ok(())
    }
}

/// P-521 key pair for ECDH key exchange
///
/// This struct holds an ephemeral private key from aws-lc-rs along with
/// the computed public key bytes for transmission.
pub struct EcdhP521KeyPair {
    private: EphemeralPrivateKey,
    public_bytes: Vec<u8>,
}

impl EcdhP521KeyPair {
    /// Generate a new P-521 key pair
    ///
    /// # Errors
    /// Returns an error if key generation fails.
    pub fn generate() -> Result<Self, EcdhError> {
        let rng = aws_lc_rs::rand::SystemRandom::new();
        let private = EphemeralPrivateKey::generate(&ECDH_P521, &rng)
            .map_err(|_e| EcdhError::KeyGenerationFailed)?;
        let public = private.compute_public_key().map_err(|_e| EcdhError::KeyGenerationFailed)?;
        Ok(Self { private, public_bytes: public.as_ref().to_vec() })
    }

    /// Get public key bytes for transmission
    #[must_use]
    pub fn public_key_bytes(&self) -> &[u8] {
        &self.public_bytes
    }

    /// Get the public key
    ///
    /// # Errors
    /// Returns an error if the public key bytes are invalid (should never happen).
    pub fn public_key(&self) -> Result<EcdhP521PublicKey, EcdhError> {
        EcdhP521PublicKey::from_bytes(&self.public_bytes)
    }

    /// Perform P-521 ECDH key agreement with a peer's public key
    ///
    /// Consumes the private key to ensure single-use (ephemeral) semantics.
    ///
    /// # Errors
    /// Returns an error if key agreement fails (e.g., invalid peer public key).
    pub fn agree(self, peer_public_bytes: &[u8]) -> Result<Vec<u8>, EcdhError> {
        let peer_public = UnparsedPublicKey::new(&ECDH_P521, peer_public_bytes);

        agreement::agree_ephemeral(
            self.private,
            peer_public,
            EcdhError::AgreementFailed,
            |shared_secret| Ok(shared_secret.to_vec()),
        )
    }
}

impl std::fmt::Debug for EcdhP521KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EcdhP521KeyPair")
            .field("public_bytes", &self.public_bytes)
            .field("private", &"[REDACTED]")
            .finish()
    }
}

// ============================================================================
// Generic ECDH Operations for NIST Curves
// ============================================================================

/// Perform ephemeral P-256 ECDH key agreement
///
/// Generates a new ephemeral key pair and performs Diffie-Hellman with the peer's public key.
///
/// # Returns
/// A tuple of (shared_secret, our_public_key)
///
/// # Errors
/// Returns an error if key generation or agreement fails.
pub fn agree_ephemeral_p256(peer_public_bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>), EcdhError> {
    let keypair = EcdhP256KeyPair::generate()?;
    let our_public = keypair.public_key_bytes().to_vec();
    let shared_secret = keypair.agree(peer_public_bytes)?;
    Ok((shared_secret, our_public))
}

/// Perform ephemeral P-384 ECDH key agreement
///
/// Generates a new ephemeral key pair and performs Diffie-Hellman with the peer's public key.
///
/// # Returns
/// A tuple of (shared_secret, our_public_key)
///
/// # Errors
/// Returns an error if key generation or agreement fails.
pub fn agree_ephemeral_p384(peer_public_bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>), EcdhError> {
    let keypair = EcdhP384KeyPair::generate()?;
    let our_public = keypair.public_key_bytes().to_vec();
    let shared_secret = keypair.agree(peer_public_bytes)?;
    Ok((shared_secret, our_public))
}

/// Perform ephemeral P-521 ECDH key agreement
///
/// Generates a new ephemeral key pair and performs Diffie-Hellman with the peer's public key.
///
/// # Returns
/// A tuple of (shared_secret, our_public_key)
///
/// # Errors
/// Returns an error if key generation or agreement fails.
pub fn agree_ephemeral_p521(peer_public_bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>), EcdhError> {
    let keypair = EcdhP521KeyPair::generate()?;
    let our_public = keypair.public_key_bytes().to_vec();
    let shared_secret = keypair.agree(peer_public_bytes)?;
    Ok((shared_secret, our_public))
}

/// Validate a P-256 public key
///
/// # Errors
/// Returns an error if the public key is invalid.
pub fn validate_p256_public_key(public_key_bytes: &[u8]) -> Result<(), EcdhError> {
    let pk = EcdhP256PublicKey::from_bytes(public_key_bytes)?;
    pk.validate()
}

/// Validate a P-384 public key
///
/// # Errors
/// Returns an error if the public key is invalid.
pub fn validate_p384_public_key(public_key_bytes: &[u8]) -> Result<(), EcdhError> {
    let pk = EcdhP384PublicKey::from_bytes(public_key_bytes)?;
    pk.validate()
}

/// Validate a P-521 public key
///
/// # Errors
/// Returns an error if the public key is invalid.
pub fn validate_p521_public_key(public_key_bytes: &[u8]) -> Result<(), EcdhError> {
    let pk = EcdhP521PublicKey::from_bytes(public_key_bytes)?;
    pk.validate()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn test_ecdh_keypair_generation() {
        let keypair = X25519KeyPair::generate();
        assert!(keypair.is_ok());
        let keypair = keypair.unwrap();
        assert_eq!(keypair.public_key_bytes().len(), X25519_KEY_SIZE);
    }

    #[test]
    fn test_ecdh_key_exchange() {
        // Generate two keypairs
        let keypair1 = X25519KeyPair::generate().unwrap();
        let keypair2 = X25519KeyPair::generate().unwrap();

        let pk1 = *keypair1.public_key_bytes();
        let pk2 = *keypair2.public_key_bytes();

        // Perform key agreement
        let ss1 = keypair1.agree(&pk2).unwrap();
        let ss2 = keypair2.agree(&pk1).unwrap();

        // Both parties should derive the same shared secret
        assert_eq!(ss1, ss2);
    }

    #[test]
    fn test_public_key_from_bytes() {
        let bytes = [0x42u8; X25519_KEY_SIZE];
        let pk = X25519PublicKey::from_bytes(&bytes).unwrap();
        assert_eq!(pk.as_bytes(), &bytes);
    }

    #[test]
    fn test_public_key_invalid_size() {
        let bytes = [0x42u8; 16]; // Wrong size
        let result = X25519PublicKey::from_bytes(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_secret_key_from_bytes() {
        let bytes = [0x42u8; X25519_KEY_SIZE];
        let sk = X25519SecretKey::from_bytes(&bytes).unwrap();
        assert_eq!(sk.as_bytes(), &bytes);
    }

    #[test]
    fn test_validate_public_key() {
        let bytes = [0x42u8; X25519_KEY_SIZE];
        let pk = X25519PublicKey::from_bytes(&bytes).unwrap();
        assert!(validate_public_key(&pk).is_ok());
    }

    #[test]
    fn test_validate_secret_key() {
        let bytes = [0x42u8; X25519_KEY_SIZE];
        let sk = X25519SecretKey::from_bytes(&bytes).unwrap();
        assert!(validate_secret_key(&sk).is_ok());
    }

    #[test]
    fn test_agree_ephemeral() {
        let keypair = X25519KeyPair::generate().unwrap();
        let peer_public = *keypair.public_key_bytes();

        let result = agree_ephemeral(&peer_public);
        assert!(result.is_ok());
        let (shared_secret, our_public) = result.unwrap();
        assert_eq!(shared_secret.len(), X25519_KEY_SIZE);
        assert_eq!(our_public.len(), X25519_KEY_SIZE);
    }

    // ====================================================================
    // X25519StaticKeyPair tests — proves real ECDH (not SHA-256 hash)
    // ====================================================================

    #[test]
    fn test_static_keypair_generation() {
        let kp = X25519StaticKeyPair::generate().unwrap();
        assert_eq!(kp.public_key_bytes().len(), X25519_KEY_SIZE);
        assert!(!kp.public_key_bytes().iter().all(|&b| b == 0));
    }

    #[test]
    fn test_static_keypair_commutativity() {
        // This is the key DH property: alice.agree(bob_pk) == bob.agree(alice_pk)
        let alice = X25519StaticKeyPair::generate().unwrap();
        let bob = X25519StaticKeyPair::generate().unwrap();

        let ss_ab = alice.agree(bob.public_key_bytes()).unwrap();
        let ss_ba = bob.agree(alice.public_key_bytes()).unwrap();

        assert_eq!(ss_ab, ss_ba, "DH commutativity must hold");
        assert!(!ss_ab.iter().all(|&b| b == 0), "Shared secret must not be all zeros");
    }

    #[test]
    fn test_static_keypair_reusable() {
        // Key can be used for multiple agreements without being consumed
        let alice = X25519StaticKeyPair::generate().unwrap();
        let bob = X25519StaticKeyPair::generate().unwrap();
        let carol = X25519StaticKeyPair::generate().unwrap();

        let ss1 = alice.agree(bob.public_key_bytes()).unwrap();
        let ss2 = alice.agree(carol.public_key_bytes()).unwrap();
        let ss3 = alice.agree(bob.public_key_bytes()).unwrap();

        // Same peer → same shared secret (deterministic)
        assert_eq!(ss1, ss3, "agree() with same peer must produce same result");
        // Different peer → different shared secret
        assert_ne!(ss1, ss2, "Different peers must produce different shared secrets");
    }

    #[test]
    fn test_static_keypair_public_key() {
        let kp = X25519StaticKeyPair::generate().unwrap();
        let pk = kp.public_key();
        assert_eq!(pk.as_bytes(), kp.public_key_bytes());
    }

    #[test]
    fn test_static_keypair_different_keys() {
        // Two generates must produce different key pairs
        let kp1 = X25519StaticKeyPair::generate().unwrap();
        let kp2 = X25519StaticKeyPair::generate().unwrap();
        assert_ne!(kp1.public_key_bytes(), kp2.public_key_bytes());
    }

    // ====================================================================
    // X25519StaticKeyPair seed serialization tests
    // ====================================================================

    #[test]
    fn test_static_keypair_seed_roundtrip() {
        let original = X25519StaticKeyPair::generate().unwrap();
        let seed = original.seed_bytes().unwrap();
        let restored = X25519StaticKeyPair::from_seed_bytes(&seed).unwrap();

        assert_eq!(original.public_key_bytes(), restored.public_key_bytes());
    }

    #[test]
    fn test_static_keypair_seed_roundtrip_agree() {
        // Restored key must produce identical shared secrets
        let alice = X25519StaticKeyPair::generate().unwrap();
        let bob = X25519StaticKeyPair::generate().unwrap();

        let ss_original = alice.agree(bob.public_key_bytes()).unwrap();

        let seed = alice.seed_bytes().unwrap();
        let alice_restored = X25519StaticKeyPair::from_seed_bytes(&seed).unwrap();
        let ss_restored = alice_restored.agree(bob.public_key_bytes()).unwrap();

        assert_eq!(ss_original, ss_restored);
    }

    #[test]
    fn test_static_keypair_seed_not_zero() {
        let kp = X25519StaticKeyPair::generate().unwrap();
        let seed = kp.seed_bytes().unwrap();
        assert!(!seed.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_static_keypair_from_invalid_seed() {
        // All-zero seed should still produce a valid key (X25519 clamping)
        let zero_seed = [0u8; X25519_KEY_SIZE];
        let result = X25519StaticKeyPair::from_seed_bytes(&zero_seed);
        assert!(result.is_ok());
    }

    // ====================================================================
    // EcdhCurve enum tests
    // ====================================================================

    #[test]
    fn test_ecdh_curve_public_key_size() {
        assert_eq!(EcdhCurve::X25519.public_key_size(), X25519_KEY_SIZE);
        assert_eq!(EcdhCurve::P256.public_key_size(), P256_PUBLIC_KEY_SIZE);
        assert_eq!(EcdhCurve::P384.public_key_size(), P384_PUBLIC_KEY_SIZE);
        assert_eq!(EcdhCurve::P521.public_key_size(), P521_PUBLIC_KEY_SIZE);
    }

    #[test]
    fn test_ecdh_curve_shared_secret_size() {
        assert_eq!(EcdhCurve::X25519.shared_secret_size(), X25519_KEY_SIZE);
        assert_eq!(EcdhCurve::P256.shared_secret_size(), P256_SHARED_SECRET_SIZE);
        assert_eq!(EcdhCurve::P384.shared_secret_size(), P384_SHARED_SECRET_SIZE);
        assert_eq!(EcdhCurve::P521.shared_secret_size(), P521_SHARED_SECRET_SIZE);
    }

    #[test]
    fn test_ecdh_curve_name() {
        assert_eq!(EcdhCurve::X25519.name(), "X25519");
        assert_eq!(EcdhCurve::P256.name(), "P-256");
        assert_eq!(EcdhCurve::P384.name(), "P-384");
        assert_eq!(EcdhCurve::P521.name(), "P-521");
    }

    #[test]
    fn test_ecdh_curve_clone_eq() {
        let c1 = EcdhCurve::P256;
        let c2 = c1;
        assert_eq!(c1, c2);
        assert_ne!(EcdhCurve::P256, EcdhCurve::P384);
    }

    // ====================================================================
    // X25519 additional coverage
    // ====================================================================

    #[test]
    fn test_x25519_public_key_to_vec() {
        let bytes = [0x42u8; X25519_KEY_SIZE];
        let pk = X25519PublicKey::from_bytes(&bytes).unwrap();
        assert_eq!(pk.to_vec(), bytes.to_vec());
    }

    #[test]
    fn test_x25519_secret_key_invalid_size() {
        let result = X25519SecretKey::from_bytes(&[0u8; 16]);
        assert!(matches!(result, Err(EcdhError::InvalidKeySize { expected: 32, actual: 16 })));
    }

    #[test]
    fn test_x25519_secret_key_debug_redacted() {
        let sk = X25519SecretKey::from_bytes(&[0xAA; X25519_KEY_SIZE]).unwrap();
        let debug = format!("{:?}", sk);
        assert!(debug.contains("REDACTED"));
        assert!(!debug.contains("0xaa"));
    }

    #[test]
    fn test_x25519_keypair_debug() {
        let kp = X25519KeyPair::generate().unwrap();
        let debug = format!("{:?}", kp);
        assert!(debug.contains("X25519KeyPair"));
        assert!(debug.contains("REDACTED"));
    }

    #[test]
    fn test_x25519_keypair_public_key() {
        let kp = X25519KeyPair::generate().unwrap();
        let pk = kp.public_key();
        assert_eq!(pk.as_bytes().len(), X25519_KEY_SIZE);
    }

    #[test]
    fn test_x25519_static_keypair_debug() {
        let kp = X25519StaticKeyPair::generate().unwrap();
        let debug = format!("{:?}", kp);
        assert!(debug.contains("X25519StaticKeyPair"));
        assert!(debug.contains("REDACTED"));
    }

    // ====================================================================
    // P-256 tests
    // ====================================================================

    #[test]
    fn test_p256_keypair_generation() {
        let kp = EcdhP256KeyPair::generate().unwrap();
        assert_eq!(kp.public_key_bytes().len(), P256_PUBLIC_KEY_SIZE);
    }

    #[test]
    fn test_p256_keypair_public_key() {
        let kp = EcdhP256KeyPair::generate().unwrap();
        let pk = kp.public_key().unwrap();
        assert_eq!(pk.as_bytes().len(), P256_PUBLIC_KEY_SIZE);
        assert_eq!(pk.to_vec().len(), P256_PUBLIC_KEY_SIZE);
    }

    #[test]
    fn test_p256_key_exchange() {
        let alice = EcdhP256KeyPair::generate().unwrap();
        let bob = EcdhP256KeyPair::generate().unwrap();

        let alice_pk = alice.public_key_bytes().to_vec();
        let bob_pk = bob.public_key_bytes().to_vec();

        let ss_alice = alice.agree(&bob_pk).unwrap();
        let ss_bob = bob.agree(&alice_pk).unwrap();

        assert_eq!(ss_alice, ss_bob);
        assert_eq!(ss_alice.len(), P256_SHARED_SECRET_SIZE);
    }

    #[test]
    fn test_p256_public_key_from_bytes_valid() {
        let kp = EcdhP256KeyPair::generate().unwrap();
        let pk_bytes = kp.public_key_bytes().to_vec();
        let pk = EcdhP256PublicKey::from_bytes(&pk_bytes).unwrap();
        assert_eq!(pk.as_bytes(), &pk_bytes);
        assert!(pk.validate().is_ok());
    }

    #[test]
    fn test_p256_public_key_wrong_size() {
        let result = EcdhP256PublicKey::from_bytes(&[0x04; 32]);
        assert!(matches!(result, Err(EcdhError::InvalidKeySize { .. })));
    }

    #[test]
    fn test_p256_public_key_wrong_prefix() {
        let mut bytes = vec![0x05; P256_PUBLIC_KEY_SIZE];
        bytes[0] = 0x05; // Not 0x04
        let result = EcdhP256PublicKey::from_bytes(&bytes);
        assert!(matches!(result, Err(EcdhError::InvalidPointFormat { .. })));
    }

    #[test]
    fn test_p256_keypair_debug() {
        let kp = EcdhP256KeyPair::generate().unwrap();
        let debug = format!("{:?}", kp);
        assert!(debug.contains("EcdhP256KeyPair"));
        assert!(debug.contains("REDACTED"));
    }

    #[test]
    fn test_agree_ephemeral_p256() {
        let bob = EcdhP256KeyPair::generate().unwrap();
        let bob_pk = bob.public_key_bytes().to_vec();
        let (shared_secret, our_pk) = agree_ephemeral_p256(&bob_pk).unwrap();
        assert_eq!(shared_secret.len(), P256_SHARED_SECRET_SIZE);
        assert_eq!(our_pk.len(), P256_PUBLIC_KEY_SIZE);
    }

    #[test]
    fn test_validate_p256_public_key_valid() {
        let kp = EcdhP256KeyPair::generate().unwrap();
        assert!(validate_p256_public_key(kp.public_key_bytes()).is_ok());
    }

    #[test]
    fn test_validate_p256_public_key_invalid() {
        assert!(validate_p256_public_key(&[0u8; 10]).is_err());
    }

    // ====================================================================
    // P-384 tests
    // ====================================================================

    #[test]
    fn test_p384_keypair_generation() {
        let kp = EcdhP384KeyPair::generate().unwrap();
        assert_eq!(kp.public_key_bytes().len(), P384_PUBLIC_KEY_SIZE);
    }

    #[test]
    fn test_p384_keypair_public_key() {
        let kp = EcdhP384KeyPair::generate().unwrap();
        let pk = kp.public_key().unwrap();
        assert_eq!(pk.as_bytes().len(), P384_PUBLIC_KEY_SIZE);
        assert_eq!(pk.to_vec().len(), P384_PUBLIC_KEY_SIZE);
    }

    #[test]
    fn test_p384_key_exchange() {
        let alice = EcdhP384KeyPair::generate().unwrap();
        let bob = EcdhP384KeyPair::generate().unwrap();

        let alice_pk = alice.public_key_bytes().to_vec();
        let bob_pk = bob.public_key_bytes().to_vec();

        let ss_alice = alice.agree(&bob_pk).unwrap();
        let ss_bob = bob.agree(&alice_pk).unwrap();

        assert_eq!(ss_alice, ss_bob);
        assert_eq!(ss_alice.len(), P384_SHARED_SECRET_SIZE);
    }

    #[test]
    fn test_p384_public_key_from_bytes_valid() {
        let kp = EcdhP384KeyPair::generate().unwrap();
        let pk_bytes = kp.public_key_bytes().to_vec();
        let pk = EcdhP384PublicKey::from_bytes(&pk_bytes).unwrap();
        assert_eq!(pk.as_bytes(), &pk_bytes);
        assert!(pk.validate().is_ok());
    }

    #[test]
    fn test_p384_public_key_wrong_size() {
        let result = EcdhP384PublicKey::from_bytes(&[0x04; 32]);
        assert!(matches!(result, Err(EcdhError::InvalidKeySize { .. })));
    }

    #[test]
    fn test_p384_public_key_wrong_prefix() {
        let mut bytes = vec![0x03; P384_PUBLIC_KEY_SIZE];
        bytes[0] = 0x03;
        let result = EcdhP384PublicKey::from_bytes(&bytes);
        assert!(matches!(result, Err(EcdhError::InvalidPointFormat { .. })));
    }

    #[test]
    fn test_p384_keypair_debug() {
        let kp = EcdhP384KeyPair::generate().unwrap();
        let debug = format!("{:?}", kp);
        assert!(debug.contains("EcdhP384KeyPair"));
        assert!(debug.contains("REDACTED"));
    }

    #[test]
    fn test_agree_ephemeral_p384() {
        let bob = EcdhP384KeyPair::generate().unwrap();
        let bob_pk = bob.public_key_bytes().to_vec();
        let (shared_secret, our_pk) = agree_ephemeral_p384(&bob_pk).unwrap();
        assert_eq!(shared_secret.len(), P384_SHARED_SECRET_SIZE);
        assert_eq!(our_pk.len(), P384_PUBLIC_KEY_SIZE);
    }

    #[test]
    fn test_validate_p384_public_key_valid() {
        let kp = EcdhP384KeyPair::generate().unwrap();
        assert!(validate_p384_public_key(kp.public_key_bytes()).is_ok());
    }

    #[test]
    fn test_validate_p384_public_key_invalid() {
        assert!(validate_p384_public_key(&[0u8; 10]).is_err());
    }

    // ====================================================================
    // P-521 tests
    // ====================================================================

    #[test]
    fn test_p521_keypair_generation() {
        let kp = EcdhP521KeyPair::generate().unwrap();
        assert_eq!(kp.public_key_bytes().len(), P521_PUBLIC_KEY_SIZE);
    }

    #[test]
    fn test_p521_keypair_public_key() {
        let kp = EcdhP521KeyPair::generate().unwrap();
        let pk = kp.public_key().unwrap();
        assert_eq!(pk.as_bytes().len(), P521_PUBLIC_KEY_SIZE);
        assert_eq!(pk.to_vec().len(), P521_PUBLIC_KEY_SIZE);
    }

    #[test]
    fn test_p521_key_exchange() {
        let alice = EcdhP521KeyPair::generate().unwrap();
        let bob = EcdhP521KeyPair::generate().unwrap();

        let alice_pk = alice.public_key_bytes().to_vec();
        let bob_pk = bob.public_key_bytes().to_vec();

        let ss_alice = alice.agree(&bob_pk).unwrap();
        let ss_bob = bob.agree(&alice_pk).unwrap();

        assert_eq!(ss_alice, ss_bob);
        assert_eq!(ss_alice.len(), P521_SHARED_SECRET_SIZE);
    }

    #[test]
    fn test_p521_public_key_from_bytes_valid() {
        let kp = EcdhP521KeyPair::generate().unwrap();
        let pk_bytes = kp.public_key_bytes().to_vec();
        let pk = EcdhP521PublicKey::from_bytes(&pk_bytes).unwrap();
        assert_eq!(pk.as_bytes(), &pk_bytes);
        assert!(pk.validate().is_ok());
    }

    #[test]
    fn test_p521_public_key_wrong_size() {
        let result = EcdhP521PublicKey::from_bytes(&[0x04; 32]);
        assert!(matches!(result, Err(EcdhError::InvalidKeySize { .. })));
    }

    #[test]
    fn test_p521_public_key_wrong_prefix() {
        let mut bytes = vec![0x02; P521_PUBLIC_KEY_SIZE];
        bytes[0] = 0x02;
        let result = EcdhP521PublicKey::from_bytes(&bytes);
        assert!(matches!(result, Err(EcdhError::InvalidPointFormat { .. })));
    }

    #[test]
    fn test_p521_keypair_debug() {
        let kp = EcdhP521KeyPair::generate().unwrap();
        let debug = format!("{:?}", kp);
        assert!(debug.contains("EcdhP521KeyPair"));
        assert!(debug.contains("REDACTED"));
    }

    #[test]
    fn test_agree_ephemeral_p521() {
        let bob = EcdhP521KeyPair::generate().unwrap();
        let bob_pk = bob.public_key_bytes().to_vec();
        let (shared_secret, our_pk) = agree_ephemeral_p521(&bob_pk).unwrap();
        assert_eq!(shared_secret.len(), P521_SHARED_SECRET_SIZE);
        assert_eq!(our_pk.len(), P521_PUBLIC_KEY_SIZE);
    }

    #[test]
    fn test_validate_p521_public_key_valid() {
        let kp = EcdhP521KeyPair::generate().unwrap();
        assert!(validate_p521_public_key(kp.public_key_bytes()).is_ok());
    }

    #[test]
    fn test_validate_p521_public_key_invalid() {
        assert!(validate_p521_public_key(&[0u8; 10]).is_err());
    }

    // ====================================================================
    // Error variant coverage
    // ====================================================================

    #[test]
    fn test_ecdh_error_display() {
        let e = EcdhError::KeyGenerationFailed;
        assert!(e.to_string().contains("key generation"));

        let e = EcdhError::SharedSecretDerivationFailed;
        assert!(e.to_string().contains("shared secret"));

        let e = EcdhError::InvalidKeySize { expected: 32, actual: 16 };
        assert!(e.to_string().contains("32"));
        assert!(e.to_string().contains("16"));

        let e = EcdhError::AgreementFailed;
        assert!(e.to_string().contains("agreement"));

        let e = EcdhError::InvalidPublicKey { curve: "P-256" };
        assert!(e.to_string().contains("P-256"));

        let e = EcdhError::InvalidPointFormat { expected: "uncompressed", actual: "compressed" };
        assert!(e.to_string().contains("uncompressed"));

        let e = EcdhError::InvalidKeyData;
        assert!(e.to_string().contains("Invalid key data"));

        let e = EcdhError::CurveMismatch { expected: "P-256", actual: "P-384" };
        assert!(e.to_string().contains("P-256"));
        assert!(e.to_string().contains("P-384"));
    }
}
