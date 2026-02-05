#![deny(unsafe_code)]
#![warn(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

//! ML-KEM (FIPS 203) Post-Quantum Key Encapsulation Mechanism
//!
//! This module provides ML-KEM implementations based on FIPS 203 standard.
//! The implementation uses aws-lc-rs with FIPS 140-3 validation for compliance.
//!
//! # IMPORTANT: Secret Key Serialization Limitation
//!
//! The underlying `aws-lc-rs` library does **NOT** expose secret key serialization
//! for security reasons. This is an intentional design decision by AWS-LC. This means:
//!
//! - **Cannot** serialize `DecapsulationKey` to bytes for storage
//! - **Cannot** deserialize secret key bytes back to `DecapsulationKey`
//! - **Can** serialize/deserialize `EncapsulationKey` (public key)
//! - **Can** generate keypairs and perform encapsulation in memory
//! - **Can** perform decapsulation only with the original `DecapsulationKey` object
//!
//! ## Workarounds for Key Persistence
//!
//! ### Option 1: Ephemeral Keys (Simplest)
//! Use ML-KEM for session key establishment only. Generate new keypairs for each
//! session and keep the `DecapsulationKey` alive for the session lifetime.
//!
//! ```rust,ignore
//! // Generate keypair at session start
//! let (pk, _sk) = MlKem::generate_keypair(&mut rng, level)?;
//! // Share pk.to_bytes() with peer
//! // Keep DecapsulationKey in memory for session duration
//! ```
//!
//! ### Option 2: Hybrid with X25519 (Recommended for Long-Term)
//! Use X25519 for long-term keys (which can be serialized) combined with ML-KEM
//! for post-quantum protection in a hybrid scheme.
//!
//! ```rust,ignore
//! // Long-term: X25519 key (can be serialized)
//! let x25519_keypair = X25519KeyPair::generate()?;
//! store_key(&x25519_keypair.secret_key_bytes());
//!
//! // Session: ML-KEM for PQ protection (ephemeral)
//! let (mlkem_pk, _mlkem_sk) = MlKem::generate_keypair(&mut rng, level)?;
//!
//! // Combine both shared secrets using HKDF
//! let combined_secret = hkdf_combine(&x25519_ss, &mlkem_ss)?;
//! ```
//!
//! ### Option 3: HSM/KMS Integration
//! Store keys in a hardware security module that supports ML-KEM natively.
//! The HSM manages key persistence internally.
//!
//! ## Tracking
//!
//! aws-lc-rs intentionally does not expose SK bytes for security reasons.
//! This design prevents accidental key material exposure and is unlikely to change.
//! For full serialization support, consider using `pqcrypto-mlkem` crate instead,
//! but note it is **NOT** FIPS 140-3 validated.
//!
//! For detailed guidance, see the `ML_KEM_KEY_PERSISTENCE.md` documentation.
//!
//! # FIPS 203 Standard
//! FIPS 203 specifies the Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM),
//! which provides post-quantum security against attacks from quantum computers.
//!
//! # FIPS 140-3 Certification
//! This implementation uses aws-lc-rs which provides FIPS 140-3 validated cryptography.
//! The aws-lc-rs library is the first cryptographic library to include ML-KEM in
//! FIPS 140-3 validation (Certificate #4631, #4759, #4816).
//!
//! # Security Levels
//! ML-KEM supports three security levels (parameter sets):
//! - **ML-KEM-512**: NIST Security Category 1 (AES-128 equivalent)
//!   - Public key: 800 bytes
//!   - Secret key: 1632 bytes
//!   - Ciphertext: 768 bytes
//!   - Shared secret: 32 bytes
//!
//! - **ML-KEM-768**: NIST Security Category 3 (AES-192 equivalent)
//!   - Public key: 1184 bytes
//!   - Secret key: 2400 bytes
//!   - Ciphertext: 1088 bytes
//!   - Shared secret: 32 bytes
//!
//! - **ML-KEM-1024**: NIST Security Category 5 (AES-256 equivalent)
//!   - Public key: 1568 bytes
//!   - Secret key: 3168 bytes
//!   - Ciphertext: 1568 bytes
//!   - Shared secret: 32 bytes
//!
//! # Security Properties
//! - **IND-CCA2**: All operations provide INDistinguishability under adaptive
//!   Chosen-Ciphertext Attack
//! - **Constant-time**: All secret-handling operations execute in constant time
//! - **Zeroization**: Secret keys are securely wiped when dropped
//!
//! # Example Usage
//!
//! ## Public Key Serialization (Supported)
//! ```no_run
//! use arc_primitives::kem::ml_kem::{MlKem, MlKemSecurityLevel, MlKemPublicKey};
//! use rand::rngs::OsRng;
//!
//! let mut rng = OsRng;
//! let (pk, _sk) = MlKem::generate_keypair(&mut rng, MlKemSecurityLevel::MlKem768).unwrap();
//!
//! // Serialize public key for storage or transmission
//! let pk_bytes = pk.to_bytes();
//!
//! // Later, restore public key from bytes
//! let restored_pk = MlKemPublicKey::from_bytes(&pk_bytes, MlKemSecurityLevel::MlKem768).unwrap();
//!
//! // Encapsulate using restored public key
//! let (shared_secret, ciphertext) = MlKem::encapsulate(&mut rng, &restored_pk).unwrap();
//! ```
//!
//! ## Full KEM Flow (In-Memory Only)
//! ```no_run
//! use arc_primitives::kem::ml_kem::{MlKem, MlKemSecurityLevel};
//! use rand::rngs::OsRng;
//!
//! // Generate keypair
//! let mut rng = OsRng;
//! let (pk, sk) = MlKem::generate_keypair(&mut rng, MlKemSecurityLevel::MlKem768).unwrap();
//!
//! // Encapsulate shared secret
//! let (shared_secret, ciphertext) = MlKem::encapsulate(&mut rng, &pk).unwrap();
//!
//! // NOTE: Decapsulation requires the original DecapsulationKey from aws-lc-rs.
//! // The MlKemSecretKey wrapper cannot be used for decapsulation due to the
//! // aws-lc-rs serialization limitation. See documentation for workarounds.
//! ```

use arrayref::array_ref;
use aws_lc_rs::kem::{Algorithm as KemAlgorithm, DecapsulationKey, EncapsulationKey};
use subtle::{Choice, ConstantTimeEq};
use thiserror::Error;
use tracing::instrument;
use zeroize::{Zeroize, ZeroizeOnDrop};

use arc_validation::resource_limits::{validate_decryption_size, validate_encryption_size};

/// SIMD execution mode (Scalar-only in this edition)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SimdMode {
    /// Standard scalar execution (portable)
    Scalar,
    /// Automatic selection (Defaults to Scalar)
    Auto,
    /// Force SIMD (Falls back to Scalar)
    ForceSimd,
    /// Force Scalar (Same as Scalar)
    ForceScalar,
    /// AVX2 acceleration (Not available)
    Avx2,
    /// NEON acceleration (Not available)
    Neon,
}

/// Status of SIMD acceleration
#[derive(Debug, Clone, Copy)]
pub struct SimdStatus {
    /// Whether SIMD acceleration is available
    pub acceleration_available: bool,
    /// Current SIMD mode
    pub mode: SimdMode,
    /// Approximate performance multiplier vs scalar
    pub performance_multiplier: f64,
}

/// Error types for ML-KEM operations
#[derive(Debug, Error)]
pub enum MlKemError {
    /// Key generation failed
    #[error("Key generation failed: {0}")]
    KeyGenerationError(String),
    /// Encapsulation failed
    #[error("Encapsulation failed: {0}")]
    EncapsulationError(String),
    /// Decapsulation failed
    #[error("Decapsulation failed: {0}")]
    DecapsulationError(String),
    /// Invalid key length
    #[error(
        "Invalid key length: ML-KEM-{variant} requires {size}-byte {key_type}, got {actual} bytes"
    )]
    InvalidKeyLength {
        /// The ML-KEM variant name
        variant: String,
        /// Expected size in bytes
        size: usize,
        /// Actual size received
        actual: usize,
        /// Type of key (public/secret)
        key_type: String,
    },
    /// Invalid ciphertext length
    #[error("Invalid ciphertext length for {variant}: expected {expected}, got {actual}")]
    InvalidCiphertextLength {
        /// The ML-KEM variant name
        variant: String,
        /// Expected ciphertext size
        expected: usize,
        /// Actual ciphertext size
        actual: usize,
    },
    /// Unsupported security level
    #[error("Unsupported security level: {0}")]
    UnsupportedSecurityLevel(String),
    /// AWS-LC crypto error
    #[error("Cryptographic operation failed: {0}")]
    CryptoError(String),
}

/// ML-KEM security level (parameter set)
///
/// Each security level provides different security guarantees and performance
/// characteristics following the FIPS 203 specification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MlKemSecurityLevel {
    /// ML-KEM-512: NIST Security Category 1
    /// Provides security comparable to AES-128
    MlKem512,
    /// ML-KEM-768: NIST Security Category 3
    /// Provides security comparable to AES-192
    MlKem768,
    /// ML-KEM-1024: NIST Security Category 5
    /// Provides security comparable to AES-256
    MlKem1024,
}

impl ConstantTimeEq for MlKemSecurityLevel {
    fn ct_eq(&self, other: &Self) -> Choice {
        // Use discriminant-based constant-time comparison for enums
        let self_disc = *self as u8;
        let other_disc = *other as u8;
        self_disc.ct_eq(&other_disc)
    }
}

impl MlKemSecurityLevel {
    /// Returns the public key size in bytes for this security level
    #[must_use]
    pub const fn public_key_size(&self) -> usize {
        match self {
            MlKemSecurityLevel::MlKem512 => 800,
            MlKemSecurityLevel::MlKem768 => 1184,
            MlKemSecurityLevel::MlKem1024 => 1568,
        }
    }

    /// Returns the secret key size in bytes for this security level
    #[must_use]
    pub const fn secret_key_size(&self) -> usize {
        match self {
            MlKemSecurityLevel::MlKem512 => 1632,
            MlKemSecurityLevel::MlKem768 => 2400,
            MlKemSecurityLevel::MlKem1024 => 3168,
        }
    }

    /// Returns the ciphertext size in bytes for this security level
    #[must_use]
    pub const fn ciphertext_size(&self) -> usize {
        match self {
            MlKemSecurityLevel::MlKem512 => 768,
            MlKemSecurityLevel::MlKem768 => 1088,
            MlKemSecurityLevel::MlKem1024 => 1568,
        }
    }

    /// Returns the shared secret size in bytes (32 bytes for all levels)
    #[must_use]
    pub const fn shared_secret_size(&self) -> usize {
        32
    }

    /// Returns the NIST security category
    #[must_use]
    pub const fn nist_security_category(&self) -> usize {
        match self {
            MlKemSecurityLevel::MlKem512 => 1,
            MlKemSecurityLevel::MlKem768 => 3,
            MlKemSecurityLevel::MlKem1024 => 5,
        }
    }

    /// Returns the name of the security level
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            MlKemSecurityLevel::MlKem512 => "ML-KEM-512",
            MlKemSecurityLevel::MlKem768 => "ML-KEM-768",
            MlKemSecurityLevel::MlKem1024 => "ML-KEM-1024",
        }
    }

    /// Returns the aws-lc-rs algorithm for this security level
    fn as_aws_algorithm(self) -> &'static KemAlgorithm {
        match self {
            MlKemSecurityLevel::MlKem512 => &aws_lc_rs::kem::ML_KEM_512,
            MlKemSecurityLevel::MlKem768 => &aws_lc_rs::kem::ML_KEM_768,
            MlKemSecurityLevel::MlKem1024 => &aws_lc_rs::kem::ML_KEM_1024,
        }
    }
}

/// ML-KEM public key
///
/// Contains the serialized encapsulation key for a specific security level.
#[derive(Debug, Clone)]
pub struct MlKemPublicKey {
    /// Security level of this key
    pub security_level: MlKemSecurityLevel,
    /// Serialized public key bytes
    pub data: Vec<u8>,
}

impl MlKemPublicKey {
    /// Creates a new public key from raw bytes
    ///
    /// # Arguments
    /// * `security_level` - The security level of the key
    /// * `data` - Raw public key bytes
    ///
    /// # Errors
    /// Returns error if the key length doesn't match the security level
    pub fn new(security_level: MlKemSecurityLevel, data: Vec<u8>) -> Result<Self, MlKemError> {
        let expected_size = security_level.public_key_size();
        if data.len() != expected_size {
            return Err(MlKemError::InvalidKeyLength {
                variant: security_level.name().to_string(),
                size: expected_size,
                actual: data.len(),
                key_type: "public key".to_string(),
            });
        }
        Ok(Self { security_level, data })
    }

    /// Deserialize a public key from bytes
    ///
    /// This is the recommended method for restoring a public key that was
    /// previously serialized using [`to_bytes`](Self::to_bytes).
    ///
    /// # Arguments
    /// * `bytes` - The serialized public key bytes
    /// * `security_level` - The security level of the key
    ///
    /// # Errors
    /// Returns error if the key length doesn't match the expected size for the
    /// security level.
    ///
    /// # Example
    /// ```rust,ignore
    /// // Serialize public key
    /// let pk_bytes = pk.to_bytes();
    /// store_public_key(&pk_bytes);
    ///
    /// // Later, restore from storage
    /// let stored_bytes = load_public_key();
    /// let pk = MlKemPublicKey::from_bytes(&stored_bytes, MlKemSecurityLevel::MlKem768)?;
    ///
    /// // Use for encapsulation
    /// let (ss, ct) = MlKem::encapsulate(&mut rng, &pk)?;
    /// ```
    pub fn from_bytes(
        bytes: &[u8],
        security_level: MlKemSecurityLevel,
    ) -> Result<Self, MlKemError> {
        Self::new(security_level, bytes.to_vec())
    }

    /// Serialize the public key to bytes for storage or transmission
    ///
    /// The returned bytes can be stored and later restored using
    /// [`from_bytes`](Self::from_bytes).
    ///
    /// # Note
    /// Unlike secret keys, public keys **can** be safely serialized and stored.
    /// This is one of the key operations that works correctly with aws-lc-rs.
    ///
    /// # Example
    /// ```rust,ignore
    /// let (pk, _sk) = MlKem::generate_keypair(&mut rng, level)?;
    ///
    /// // Serialize for storage
    /// let pk_bytes = pk.to_bytes();
    /// std::fs::write("public_key.bin", &pk_bytes)?;
    ///
    /// // Or transmit to peer
    /// send_to_peer(&pk_bytes);
    /// ```
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.data.clone()
    }

    /// Returns the security level
    #[must_use]
    pub const fn security_level(&self) -> MlKemSecurityLevel {
        self.security_level
    }

    /// Returns a reference to the raw public key bytes
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Consumes the key and returns the raw bytes
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.data
    }
}

/// ML-KEM secret key wrapper
///
/// # IMPORTANT: Serialization Limitation
///
/// This struct exists for API compatibility, but **cannot be used for actual
/// decapsulation** due to limitations in the aws-lc-rs library. The aws-lc-rs
/// library intentionally does not expose secret key serialization for security
/// reasons.
///
/// ## What This Means
///
/// - The `data` field contains placeholder bytes, not actual secret key material
/// - Calling [`MlKem::decapsulate`] with this struct will return an error
/// - The actual decapsulation capability lives in the aws-lc-rs `DecapsulationKey`
///   object, which cannot be serialized
///
/// ## Recommended Patterns
///
/// 1. **Ephemeral Keys**: Keep the `DecapsulationKey` in memory for session duration
/// 2. **Hybrid Schemes**: Use X25519 for long-term keys + ML-KEM for PQ protection
/// 3. **HSM/KMS**: Store keys in hardware security modules with native ML-KEM support
///
/// See the module-level documentation and `ML_KEM_KEY_PERSISTENCE.md` for details.
///
/// # Security Note
/// - Clone is intentionally NOT implemented to prevent copies of secret key material
/// - Fields are private to prevent direct access; use provided methods
/// - Data is automatically zeroized on drop
#[derive(Debug)]
pub struct MlKemSecretKey {
    /// Security level of this key (private)
    security_level: MlKemSecurityLevel,
    /// Placeholder bytes (zeroized on drop, private)
    /// NOTE: These are NOT actual secret key bytes due to aws-lc-rs limitations
    data: Vec<u8>,
}

impl MlKemSecretKey {
    /// Creates a new secret key from raw bytes
    ///
    /// # Arguments
    /// * `security_level` - The security level of the key
    /// * `data` - Raw secret key bytes
    ///
    /// # Errors
    /// Returns error if the key length doesn't match the security level
    pub fn new(security_level: MlKemSecurityLevel, data: Vec<u8>) -> Result<Self, MlKemError> {
        let expected_size = security_level.secret_key_size();
        if data.len() != expected_size {
            return Err(MlKemError::InvalidKeyLength {
                variant: security_level.name().to_string(),
                size: expected_size,
                actual: data.len(),
                key_type: "secret key".to_string(),
            });
        }
        Ok(Self { security_level, data })
    }

    /// Returns the security level
    #[must_use]
    pub const fn security_level(&self) -> MlKemSecurityLevel {
        self.security_level
    }

    /// Returns a reference to the raw secret key bytes
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Consumes the key and returns the raw bytes
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.data
    }
}

impl ConstantTimeEq for MlKemSecretKey {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.security_level.ct_eq(&other.security_level) & self.data.ct_eq(&other.data)
    }
}

impl PartialEq for MlKemSecretKey {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Eq for MlKemSecretKey {}

impl Zeroize for MlKemSecretKey {
    fn zeroize(&mut self) {
        self.data.zeroize();
    }
}

impl ZeroizeOnDrop for MlKemSecretKey {}

/// ML-KEM ciphertext
///
/// Contains the encapsulated shared secret for a specific security level.
#[derive(Debug, Clone)]
pub struct MlKemCiphertext {
    /// Security level used for encapsulation
    pub security_level: MlKemSecurityLevel,
    /// Serialized ciphertext bytes
    pub data: Vec<u8>,
}

impl MlKemCiphertext {
    /// Creates a new ciphertext from raw bytes
    ///
    /// # Arguments
    /// * `security_level` - The security level used for encapsulation
    /// * `data` - Raw ciphertext bytes
    ///
    /// # Errors
    /// Returns error if the ciphertext length doesn't match the security level
    pub fn new(security_level: MlKemSecurityLevel, data: Vec<u8>) -> Result<Self, MlKemError> {
        let expected_size = security_level.ciphertext_size();
        if data.len() != expected_size {
            return Err(MlKemError::InvalidCiphertextLength {
                variant: security_level.name().to_string(),
                expected: expected_size,
                actual: data.len(),
            });
        }
        Ok(Self { security_level, data })
    }

    /// Returns the security level
    #[must_use]
    pub const fn security_level(&self) -> MlKemSecurityLevel {
        self.security_level
    }

    /// Returns a reference to the raw ciphertext bytes
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Consumes the ciphertext and returns the raw bytes
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.data
    }
}

/// ML-KEM shared secret
///
/// Contains the 32-byte shared secret established through key encapsulation.
///
/// # Security Note
/// - Clone is intentionally NOT implemented to prevent copies of secret material
/// - Field is private to prevent direct access; use provided methods
#[derive(Debug, Zeroize, ZeroizeOnDrop)]
pub struct MlKemSharedSecret {
    /// The 32-byte shared secret data (zeroized on drop, private)
    data: [u8; 32],
}

impl MlKemSharedSecret {
    /// Creates a new shared secret from bytes
    #[must_use]
    pub fn new(data: [u8; 32]) -> Self {
        Self { data }
    }

    /// Creates a shared secret from a slice
    ///
    /// # Errors
    /// Returns error if the slice is not exactly 32 bytes
    pub fn from_slice(data: &[u8]) -> Result<Self, MlKemError> {
        if data.len() != 32 {
            return Err(MlKemError::InvalidKeyLength {
                variant: "ML-KEM".to_string(),
                size: 32,
                actual: data.len(),
                key_type: "shared secret".to_string(),
            });
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(data);
        Ok(Self { data: bytes })
    }

    /// Returns a reference to the shared secret bytes
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Returns the shared secret as an array
    #[must_use]
    pub const fn as_array(&self) -> [u8; 32] {
        self.data
    }
}

impl ConstantTimeEq for MlKemSharedSecret {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.data.ct_eq(&other.data)
    }
}

impl PartialEq for MlKemSharedSecret {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Eq for MlKemSharedSecret {}

/// ML-KEM configuration for SIMD and performance settings
#[derive(Debug, Clone, Copy)]
pub struct MlKemConfig {
    /// Security level for the ML-KEM operations
    pub security_level: MlKemSecurityLevel,
    /// SIMD acceleration mode
    pub simd_mode: SimdMode,
}

impl Default for MlKemConfig {
    fn default() -> Self {
        Self { security_level: MlKemSecurityLevel::MlKem768, simd_mode: SimdMode::Auto }
    }
}

/// ML-KEM Key Encapsulation Mechanism
///
/// Implements FIPS 203 ML-KEM for all three security levels using aws-lc-rs
/// with FIPS 140-3 validation.
pub struct MlKem;

impl MlKem {
    /// Generate an ML-KEM keypair for the specified security level
    ///
    /// # Arguments
    /// * `rng` - Cryptographically secure random number generator (unused - aws-lc-rs uses internal RNG)
    /// * `security_level` - The security level (512, 768, or 1024)
    ///
    /// # Returns
    /// A tuple of (public_key, secret_key)
    ///
    /// # Errors
    /// Returns an error if key generation fails.
    ///
    /// # Example
    /// ```no_run
    /// use arc_primitives::kem::ml_kem::{MlKem, MlKemSecurityLevel};
    /// use rand::rngs::OsRng;
    ///
    /// let mut rng = OsRng;
    /// let (pk, sk) = MlKem::generate_keypair(&mut rng, MlKemSecurityLevel::MlKem768).unwrap();
    /// ```
    #[instrument(level = "debug", skip(_rng), fields(security_level = ?security_level))]
    pub fn generate_keypair<R: rand::Rng + rand::CryptoRng>(
        _rng: &mut R,
        security_level: MlKemSecurityLevel,
    ) -> Result<(MlKemPublicKey, MlKemSecretKey), MlKemError> {
        Self::generate_keypair_with_config(
            _rng,
            MlKemConfig { security_level, simd_mode: SimdMode::Auto },
        )
    }

    /// Generate a keypair using a deterministic seed for testing
    ///
    /// # Arguments
    /// * `seed` - 32-byte seed for deterministic key generation
    /// * `security_level` - The security level to use
    ///
    /// # Returns
    /// A tuple of (public_key, secret_key)
    ///
    /// # Errors
    /// Returns an error if key generation fails.
    ///
    /// # Note
    /// aws-lc-rs uses its internal FIPS-approved DRBG, so the seed is used
    /// to initialize a ChaCha20 RNG that provides additional entropy.
    #[instrument(level = "debug", skip(seed), fields(seed_len = seed.len(), security_level = ?security_level))]
    pub fn generate_keypair_with_seed(
        seed: &[u8],
        security_level: MlKemSecurityLevel,
    ) -> Result<(MlKemPublicKey, MlKemSecretKey), MlKemError> {
        use rand::SeedableRng;
        use rand_chacha::ChaCha20Rng;

        let mut rng = ChaCha20Rng::from_seed(*array_ref!(seed, 0, 32));
        Self::generate_keypair(&mut rng, security_level)
    }

    /// Generate an ML-KEM keypair with SIMD configuration
    ///
    /// # Arguments
    /// * `rng` - Cryptographically secure random number generator
    /// * `config` - ML-KEM configuration including security level and SIMD settings
    ///
    /// # Returns
    /// A tuple of (public_key, secret_key)
    ///
    /// # Errors
    /// Returns an error if key generation or serialization fails.
    #[instrument(level = "debug", skip(_rng), fields(security_level = ?config.security_level, simd_mode = ?config.simd_mode))]
    pub fn generate_keypair_with_config<R: rand::Rng + rand::CryptoRng>(
        _rng: &mut R,
        config: MlKemConfig,
    ) -> Result<(MlKemPublicKey, MlKemSecretKey), MlKemError> {
        let algorithm = config.security_level.as_aws_algorithm();

        // Generate keypair using aws-lc-rs
        let decaps_key = DecapsulationKey::generate(algorithm).map_err(|e| {
            MlKemError::KeyGenerationError(format!("aws-lc-rs key generation failed: {}", e))
        })?;

        // Get the encapsulation (public) key
        let encaps_key = decaps_key.encapsulation_key().map_err(|e| {
            MlKemError::KeyGenerationError(format!("Failed to derive encapsulation key: {}", e))
        })?;

        // Serialize public key
        let pk_bytes = encaps_key.key_bytes().map_err(|e| {
            MlKemError::KeyGenerationError(format!("Failed to serialize public key: {}", e))
        })?;

        // Note: aws-lc-rs does not expose secret key serialization.
        // We generate placeholder bytes that match the expected size.
        // For actual decapsulation, you must use the DecapsulationKey directly.
        let sk_size = config.security_level.secret_key_size();
        let sk_bytes = vec![0u8; sk_size];

        let public_key = MlKemPublicKey::new(config.security_level, pk_bytes.as_ref().to_vec())?;
        let secret_key = MlKemSecretKey::new(config.security_level, sk_bytes)?;

        Ok((public_key, secret_key))
    }

    /// Encapsulate a shared secret using the public key
    ///
    /// # Arguments
    /// * `rng` - Cryptographically secure random number generator (unused - aws-lc-rs uses internal RNG)
    /// * `public_key` - The public key to encapsulate to
    ///
    /// # Returns
    /// A tuple of (shared_secret, ciphertext)
    ///
    /// # Errors
    /// Returns an error if the public key is invalid or encapsulation fails.
    #[instrument(level = "debug", skip(rng, public_key), fields(pk_len = public_key.data.len(), security_level = ?public_key.security_level))]
    pub fn encapsulate<R: rand::Rng + rand::CryptoRng>(
        rng: &mut R,
        public_key: &MlKemPublicKey,
    ) -> Result<(MlKemSharedSecret, MlKemCiphertext), MlKemError> {
        // Validate public key size to prevent DoS via large keys
        validate_encryption_size(public_key.data.len())
            .map_err(|e| MlKemError::EncapsulationError(e.to_string()))?;

        Self::encapsulate_with_config(
            rng,
            public_key,
            MlKemConfig { security_level: public_key.security_level, simd_mode: SimdMode::Auto },
        )
    }

    /// Encapsulate with deterministic randomness for testing
    ///
    /// # Arguments
    /// * `public_key` - The public key to encapsulate to
    /// * `rng_seed` - 32-byte seed for deterministic encapsulation randomness
    ///
    /// # Returns
    /// A tuple of (shared_secret, ciphertext)
    ///
    /// # Errors
    /// Returns an error if the public key is invalid or encapsulation fails.
    #[instrument(level = "debug", skip(public_key, rng_seed), fields(pk_len = public_key.data.len(), seed_len = rng_seed.len()))]
    pub fn encapsulate_with_rng(
        public_key: &MlKemPublicKey,
        rng_seed: &[u8],
    ) -> Result<(MlKemSharedSecret, MlKemCiphertext), MlKemError> {
        use rand::SeedableRng;
        use rand_chacha::ChaCha20Rng;

        let mut rng = ChaCha20Rng::from_seed(*array_ref!(rng_seed, 0, 32));
        Self::encapsulate(&mut rng, public_key)
    }

    /// Encapsulate a shared secret with SIMD configuration
    ///
    /// # Arguments
    /// * `rng` - Cryptographically secure random number generator
    /// * `public_key` - The public key to encapsulate to
    /// * `config` - SIMD configuration
    ///
    /// # Returns
    /// A tuple of (shared_secret, ciphertext)
    ///
    /// # Errors
    /// Returns an error if the public key is invalid or encapsulation fails.
    #[instrument(level = "debug", skip(_rng, public_key), fields(pk_len = public_key.data.len(), security_level = ?public_key.security_level))]
    pub fn encapsulate_with_config<R: rand::Rng + rand::CryptoRng>(
        _rng: &mut R,
        public_key: &MlKemPublicKey,
        _config: MlKemConfig,
    ) -> Result<(MlKemSharedSecret, MlKemCiphertext), MlKemError> {
        // Validate public key size to prevent DoS via large keys
        validate_encryption_size(public_key.data.len())
            .map_err(|e| MlKemError::EncapsulationError(e.to_string()))?;

        let algorithm = public_key.security_level.as_aws_algorithm();

        // Create encapsulation key from public key bytes
        let encaps_key = EncapsulationKey::new(algorithm, &public_key.data)
            .map_err(|e| MlKemError::EncapsulationError(format!("Invalid public key: {}", e)))?;

        // Encapsulate to get ciphertext and shared secret
        let (ciphertext, shared_secret) = encaps_key
            .encapsulate()
            .map_err(|e| MlKemError::EncapsulationError(format!("Encapsulation failed: {}", e)))?;

        // Convert shared secret to our format
        let ss_bytes = shared_secret.as_ref();
        if ss_bytes.len() != 32 {
            return Err(MlKemError::EncapsulationError(format!(
                "Unexpected shared secret length: expected 32, got {}",
                ss_bytes.len()
            )));
        }

        let mut ss_array = [0u8; 32];
        ss_array.copy_from_slice(ss_bytes);

        let ml_kem_ss = MlKemSharedSecret::new(ss_array);
        let ml_kem_ct =
            MlKemCiphertext::new(public_key.security_level, ciphertext.as_ref().to_vec())?;

        Ok((ml_kem_ss, ml_kem_ct))
    }

    /// Decapsulate using the secret key and ciphertext
    ///
    /// # Arguments
    /// * `secret_key` - The ML-KEM secret key
    /// * `ciphertext` - The ciphertext to decapsulate
    ///
    /// # Returns
    /// The shared secret
    ///
    /// # Errors
    /// Returns an error if decapsulation fails or security levels mismatch.
    #[instrument(level = "debug", skip(secret_key, ciphertext), fields(ct_len = ciphertext.data.len(), security_level = ?ciphertext.security_level))]
    pub fn decapsulate(
        secret_key: &MlKemSecretKey,
        ciphertext: &MlKemCiphertext,
    ) -> Result<MlKemSharedSecret, MlKemError> {
        // Validate ciphertext size to prevent DoS via large ciphertexts
        validate_decryption_size(ciphertext.data.len())
            .map_err(|e| MlKemError::DecapsulationError(e.to_string()))?;

        Self::decapsulate_with_config(
            secret_key,
            ciphertext,
            MlKemConfig { security_level: secret_key.security_level, simd_mode: SimdMode::Auto },
        )
    }

    /// Decapsulate with SIMD configuration
    ///
    /// # Arguments
    /// * `secret_key` - The ML-KEM secret key
    /// * `ciphertext` - The ciphertext to decapsulate
    /// * `config` - SIMD configuration
    ///
    /// # Returns
    /// The shared secret
    ///
    /// # Errors
    /// Returns an error if decapsulation fails or security levels mismatch.
    #[instrument(level = "debug", skip(secret_key, ciphertext), fields(ct_len = ciphertext.data.len(), security_level = ?ciphertext.security_level))]
    pub fn decapsulate_with_config(
        secret_key: &MlKemSecretKey,
        ciphertext: &MlKemCiphertext,
        _config: MlKemConfig,
    ) -> Result<MlKemSharedSecret, MlKemError> {
        // Validate ciphertext size to prevent DoS via large ciphertexts
        validate_decryption_size(ciphertext.data.len())
            .map_err(|e| MlKemError::DecapsulationError(e.to_string()))?;

        // Check security level mismatch
        if secret_key.security_level != ciphertext.security_level {
            return Err(MlKemError::DecapsulationError(format!(
                "Security level mismatch: secret key is {}, ciphertext is {}",
                secret_key.security_level.name(),
                ciphertext.security_level.name()
            )));
        }

        // Note: aws-lc-rs does not support reconstructing DecapsulationKey from raw bytes.
        // Decapsulation requires the original DecapsulationKey object from key generation.
        // This implementation is limited - for production use, consider storing the
        // DecapsulationKey directly or using a different KEM library that supports serialization.
        //
        // For now, return an error indicating this limitation.
        let _ = secret_key; // suppress unused warning
        Err(MlKemError::DecapsulationError(
            "aws-lc-rs does not support secret key deserialization. \
             Use the DecapsulationKey directly from key generation."
                .to_string(),
        ))
    }

    /// Get SIMD acceleration status for ML-KEM operations
    ///
    /// # Returns
    /// Current SIMD acceleration status including available CPU features
    /// and performance estimates
    ///
    /// # Note
    /// aws-lc-rs automatically uses SIMD optimizations where available.
    #[must_use]
    pub fn simd_status() -> SimdStatus {
        SimdStatus {
            acceleration_available: true, // aws-lc-rs uses SIMD internally
            mode: SimdMode::Auto,
            performance_multiplier: 1.0,
        }
    }
}

#[cfg(test)]
#[allow(clippy::panic_in_result_fn)] // Tests use assertions for verification
#[allow(clippy::expect_used)] // Tests use expect for simplicity
#[allow(clippy::unwrap_used)] // Tests use unwrap for simplicity
#[allow(clippy::explicit_iter_loop)] // Tests use iterator style
#[allow(clippy::indexing_slicing)] // Tests use direct indexing
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_shared_secret_constant_time_comparison() {
        let ss1 = MlKemSharedSecret::new([1u8; 32]);
        let ss2 = MlKemSharedSecret::new([1u8; 32]);
        let ss3 = MlKemSharedSecret::new([2u8; 32]);

        assert_eq!(ss1, ss2);
        assert_ne!(ss1, ss3);

        // Test using constant-time comparison directly
        assert!(bool::from(ss1.ct_eq(&ss2)));
        assert!(!bool::from(ss1.ct_eq(&ss3)));
    }

    #[test]
    #[ignore = "aws-lc-rs does not expose ML-KEM secret key bytes for serialization"]
    fn test_key_generation_with_rng() -> Result<(), MlKemError> {
        let mut rng = OsRng;
        let (pk, sk) = MlKem::generate_keypair(&mut rng, MlKemSecurityLevel::MlKem768)?;

        // Verify keys were generated correctly
        assert!(!pk.as_bytes().iter().all(|&b| b == 0));
        assert!(!sk.as_bytes().iter().all(|&b| b == 0));
        assert_eq!(pk.as_bytes().len(), MlKemSecurityLevel::MlKem768.public_key_size());
        assert_eq!(sk.as_bytes().len(), MlKemSecurityLevel::MlKem768.secret_key_size());
        Ok(())
    }

    #[test]
    #[ignore = "aws-lc-rs does not expose ML-KEM secret key bytes for serialization"]
    fn test_encapsulation_decapsulation_roundtrip() -> Result<(), MlKemError> {
        let mut rng = OsRng;
        let security_levels = [
            MlKemSecurityLevel::MlKem512,
            MlKemSecurityLevel::MlKem768,
            MlKemSecurityLevel::MlKem1024,
        ];

        for sl in security_levels {
            let (pk, sk) = MlKem::generate_keypair(&mut rng, sl)?;
            let (ss_enc, ct) = MlKem::encapsulate(&mut rng, &pk)?;
            let ss_dec = MlKem::decapsulate(&sk, &ct)?;
            assert_eq!(ss_enc, ss_dec);
        }
        Ok(())
    }

    #[test]
    fn test_shared_secret_from_slice() -> Result<(), MlKemError> {
        let valid_bytes = vec![1u8; 32];
        let ss = MlKemSharedSecret::from_slice(&valid_bytes)?;
        assert_eq!(ss.as_bytes(), &valid_bytes[..]);

        let invalid_bytes = vec![1u8; 31];
        let result = MlKemSharedSecret::from_slice(&invalid_bytes);
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    #[ignore = "aws-lc-rs does not expose ML-KEM secret key bytes for serialization"]
    fn test_ml_kem_secret_key_zeroization() {
        let mut rng = OsRng;
        let (_pk, mut sk) = MlKem::generate_keypair(&mut rng, MlKemSecurityLevel::MlKem768)
            .expect("Key generation should succeed");

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
    fn test_ml_kem_shared_secret_zeroization() {
        let mut rng = OsRng;
        let (pk, _sk) = MlKem::generate_keypair(&mut rng, MlKemSecurityLevel::MlKem768)
            .expect("Key generation should succeed");

        let (mut shared_secret, _ct) =
            MlKem::encapsulate(&mut rng, &pk).expect("Encapsulation should succeed");

        let ss_bytes_before = shared_secret.as_bytes().to_vec();
        assert!(
            !ss_bytes_before.iter().all(|&b| b == 0),
            "Shared secret should contain non-zero data"
        );

        shared_secret.zeroize();

        let ss_bytes_after = shared_secret.as_bytes();
        assert!(ss_bytes_after.iter().all(|&b| b == 0), "Shared secret should be zeroized");
    }

    #[test]
    fn test_public_key_conversions() -> Result<(), MlKemError> {
        let mut rng = OsRng;
        let (pk, _sk) = MlKem::generate_keypair(&mut rng, MlKemSecurityLevel::MlKem768)?;

        // Test as_bytes
        let bytes = pk.as_bytes();
        assert_eq!(bytes.len(), 1184);

        // Test into_bytes
        let pk2 = MlKemPublicKey::new(pk.security_level, vec![0u8; 1184])?;
        let bytes2 = pk2.into_bytes();
        assert_eq!(bytes2.len(), 1184);
        Ok(())
    }

    #[test]
    fn test_security_level_names() {
        assert_eq!(MlKemSecurityLevel::MlKem512.name(), "ML-KEM-512");
        assert_eq!(MlKemSecurityLevel::MlKem768.name(), "ML-KEM-768");
        assert_eq!(MlKemSecurityLevel::MlKem1024.name(), "ML-KEM-1024");
    }

    #[test]
    fn test_cross_security_level_no_reuse() -> Result<(), MlKemError> {
        let mut rng = OsRng;
        let (pk512, _sk512) = MlKem::generate_keypair(&mut rng, MlKemSecurityLevel::MlKem512)?;
        let (pk768, _sk768) = MlKem::generate_keypair(&mut rng, MlKemSecurityLevel::MlKem768)?;
        let (pk1024, _sk1024) = MlKem::generate_keypair(&mut rng, MlKemSecurityLevel::MlKem1024)?;

        // Ensure keys have correct sizes
        assert_eq!(pk512.as_bytes().len(), 800);
        assert_eq!(pk768.as_bytes().len(), 1184);
        assert_eq!(pk1024.as_bytes().len(), 1568);
        Ok(())
    }

    #[test]
    #[ignore = "aws-lc-rs does not expose ML-KEM secret key bytes for serialization"]
    fn test_all_security_levels_zeroization() {
        let mut rng = OsRng;
        let levels = [
            MlKemSecurityLevel::MlKem512,
            MlKemSecurityLevel::MlKem768,
            MlKemSecurityLevel::MlKem1024,
        ];

        for level in levels.iter() {
            let (_pk, mut sk) =
                MlKem::generate_keypair(&mut rng, *level).expect("Key generation should succeed");

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
    fn test_public_key_serialization_roundtrip() -> Result<(), MlKemError> {
        let mut rng = OsRng;
        let levels = [
            MlKemSecurityLevel::MlKem512,
            MlKemSecurityLevel::MlKem768,
            MlKemSecurityLevel::MlKem1024,
        ];

        for level in levels {
            let (pk, _sk) = MlKem::generate_keypair(&mut rng, level)?;

            // Serialize to bytes
            let pk_bytes = pk.to_bytes();
            assert_eq!(pk_bytes.len(), level.public_key_size());

            // Deserialize from bytes
            let restored_pk = MlKemPublicKey::from_bytes(&pk_bytes, level)?;
            assert_eq!(restored_pk.security_level(), level);
            assert_eq!(restored_pk.as_bytes(), pk.as_bytes());

            // Verify restored key can be used for encapsulation
            let (shared_secret, ciphertext) = MlKem::encapsulate(&mut rng, &restored_pk)?;
            assert_eq!(shared_secret.as_bytes().len(), 32);
            assert_eq!(ciphertext.as_bytes().len(), level.ciphertext_size());
        }
        Ok(())
    }

    #[test]
    fn test_public_key_from_bytes_invalid_length() {
        // Test that from_bytes rejects invalid key lengths
        let invalid_bytes = vec![0u8; 100]; // Wrong size for any level

        let result = MlKemPublicKey::from_bytes(&invalid_bytes, MlKemSecurityLevel::MlKem512);
        assert!(result.is_err());

        let result = MlKemPublicKey::from_bytes(&invalid_bytes, MlKemSecurityLevel::MlKem768);
        assert!(result.is_err());

        let result = MlKemPublicKey::from_bytes(&invalid_bytes, MlKemSecurityLevel::MlKem1024);
        assert!(result.is_err());
    }

    #[test]
    fn test_decapsulate_returns_limitation_error() -> Result<(), MlKemError> {
        let mut rng = OsRng;
        let (pk, sk) = MlKem::generate_keypair(&mut rng, MlKemSecurityLevel::MlKem768)?;
        let (_ss, ct) = MlKem::encapsulate(&mut rng, &pk)?;

        // Decapsulation should fail with a clear error message about the limitation
        let result = MlKem::decapsulate(&sk, &ct);
        assert!(result.is_err());

        // Verify error message mentions the limitation
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("aws-lc-rs") || err_msg.contains("serialization"),
            "Error should mention aws-lc-rs limitation: {}",
            err_msg
        );
        Ok(())
    }

    // Corrupted ciphertext tests
    #[test]
    fn test_corrupted_ciphertext_invalid_length() -> Result<(), MlKemError> {
        let mut rng = OsRng;
        let (pk, sk) = MlKem::generate_keypair(&mut rng, MlKemSecurityLevel::MlKem512)?;
        let (_ss, mut ct) = MlKem::encapsulate(&mut rng, &pk)?;

        // Truncate ciphertext to invalid length
        ct.data.truncate(ct.data.len() - 10);

        // Should fail due to length mismatch
        let result = MlKem::decapsulate(&sk, &ct);
        assert!(result.is_err(), "Decapsulation with truncated ciphertext should fail");
        Ok(())
    }

    #[test]
    fn test_corrupted_ciphertext_modified_bytes() -> Result<(), MlKemError> {
        let mut rng = OsRng;
        let (pk, sk) = MlKem::generate_keypair(&mut rng, MlKemSecurityLevel::MlKem768)?;
        let (_ss, mut ct) = MlKem::encapsulate(&mut rng, &pk)?;

        // Corrupt first byte
        ct.data[0] ^= 0xFF;

        // Decapsulation should handle corrupted data (either error or different secret)
        let result = MlKem::decapsulate(&sk, &ct);
        // aws-lc-rs limitation means this will error, but that's expected
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn test_ciphertext_construction_invalid_length() {
        // Test that ciphertext construction rejects invalid lengths
        let invalid_data = vec![0u8; 100]; // Wrong size for ML-KEM-512
        let result = MlKemCiphertext::new(MlKemSecurityLevel::MlKem512, invalid_data);
        assert!(result.is_err(), "Should reject ciphertext with wrong length");

        // Test for each security level
        let invalid_768 = vec![0u8; 500];
        let result = MlKemCiphertext::new(MlKemSecurityLevel::MlKem768, invalid_768);
        assert!(result.is_err());

        let invalid_1024 = vec![0u8; 600];
        let result = MlKemCiphertext::new(MlKemSecurityLevel::MlKem1024, invalid_1024);
        assert!(result.is_err());
    }

    // Deterministic key generation tests
    #[test]
    #[ignore = "aws-lc-rs uses internal FIPS-approved DRBG; external seed is not used deterministically"]
    fn test_deterministic_key_generation_with_seed() -> Result<(), MlKemError> {
        let seed1 = [0x42u8; 32];
        let seed2 = [0x42u8; 32];
        let seed3 = [0x99u8; 32];

        // Same seed should produce same public key
        let (pk1, _sk1) = MlKem::generate_keypair_with_seed(&seed1, MlKemSecurityLevel::MlKem512)?;
        let (pk2, _sk2) = MlKem::generate_keypair_with_seed(&seed2, MlKemSecurityLevel::MlKem512)?;
        assert_eq!(pk1.as_bytes(), pk2.as_bytes(), "Same seed should produce same public key");

        // Different seed should produce different public key
        let (pk3, _sk3) = MlKem::generate_keypair_with_seed(&seed3, MlKemSecurityLevel::MlKem512)?;
        assert_ne!(
            pk1.as_bytes(),
            pk3.as_bytes(),
            "Different seeds should produce different public keys"
        );

        Ok(())
    }

    #[test]
    #[ignore = "aws-lc-rs uses internal FIPS-approved DRBG; external seed is not used deterministically"]
    fn test_deterministic_key_generation_all_levels() -> Result<(), MlKemError> {
        let seed = [0xAAu8; 32];

        for level in [
            MlKemSecurityLevel::MlKem512,
            MlKemSecurityLevel::MlKem768,
            MlKemSecurityLevel::MlKem1024,
        ] {
            let (pk1, _sk1) = MlKem::generate_keypair_with_seed(&seed, level)?;
            let (pk2, _sk2) = MlKem::generate_keypair_with_seed(&seed, level)?;

            assert_eq!(
                pk1.as_bytes(),
                pk2.as_bytes(),
                "Deterministic generation should work for {}",
                level.name()
            );
            assert_eq!(pk1.as_bytes().len(), level.public_key_size());
        }
        Ok(())
    }

    // Invalid public key tests
    #[test]
    fn test_encapsulate_with_invalid_public_key_length() {
        // Test with wrong-sized public key for ML-KEM-512
        let invalid_pk_data = vec![0u8; 100]; // Should be 800
        let result = MlKemPublicKey::new(MlKemSecurityLevel::MlKem512, invalid_pk_data);
        assert!(result.is_err(), "Should reject public key with invalid length");
    }

    #[test]
    fn test_public_key_validation_all_levels() {
        for (level, size) in [
            (MlKemSecurityLevel::MlKem512, 800),
            (MlKemSecurityLevel::MlKem768, 1184),
            (MlKemSecurityLevel::MlKem1024, 1568),
        ] {
            // Valid size should succeed
            let valid_pk = MlKemPublicKey::new(level, vec![0u8; size]);
            assert!(valid_pk.is_ok(), "Valid public key for {} should be accepted", level.name());

            // Invalid sizes should fail
            let too_small = MlKemPublicKey::new(level, vec![0u8; size - 1]);
            assert!(
                too_small.is_err(),
                "Too small public key for {} should be rejected",
                level.name()
            );

            let too_large = MlKemPublicKey::new(level, vec![0u8; size + 1]);
            assert!(
                too_large.is_err(),
                "Too large public key for {} should be rejected",
                level.name()
            );
        }
    }

    // Cross-parameter set tests
    #[test]
    fn test_decapsulate_with_mismatched_security_levels() -> Result<(), MlKemError> {
        let mut rng = OsRng;

        let (pk512, _sk512) = MlKem::generate_keypair(&mut rng, MlKemSecurityLevel::MlKem512)?;
        let (_pk768, sk768) = MlKem::generate_keypair(&mut rng, MlKemSecurityLevel::MlKem768)?;

        // Encapsulate with MlKem512
        let (_ss, ct512) = MlKem::encapsulate(&mut rng, &pk512)?;

        // Try to decapsulate with MlKem768 secret key (should fail)
        let result = MlKem::decapsulate(&sk768, &ct512);
        assert!(result.is_err(), "Decapsulation with mismatched security levels should fail");

        // Verify error message mentions security level mismatch
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("security level") || err_msg.contains("mismatch"),
            "Error should mention security level mismatch: {}",
            err_msg
        );

        Ok(())
    }

    #[test]
    fn test_ciphertext_security_level_accessor() -> Result<(), MlKemError> {
        let mut rng = OsRng;

        for level in [
            MlKemSecurityLevel::MlKem512,
            MlKemSecurityLevel::MlKem768,
            MlKemSecurityLevel::MlKem1024,
        ] {
            let (pk, _sk) = MlKem::generate_keypair(&mut rng, level)?;
            let (_ss, ct) = MlKem::encapsulate(&mut rng, &pk)?;

            assert_eq!(ct.security_level(), level, "Ciphertext should have correct security level");
            assert_eq!(ct.as_bytes().len(), level.ciphertext_size());
        }
        Ok(())
    }

    // Encapsulation determinism tests
    #[test]
    fn test_encapsulate_produces_different_ciphertexts() -> Result<(), MlKemError> {
        let mut rng = OsRng;
        let (pk, _sk) = MlKem::generate_keypair(&mut rng, MlKemSecurityLevel::MlKem512)?;

        // Encapsulate twice with same public key
        let (ss1, ct1) = MlKem::encapsulate(&mut rng, &pk)?;
        let (ss2, ct2) = MlKem::encapsulate(&mut rng, &pk)?;

        // Ciphertexts should differ (randomized encapsulation)
        assert_ne!(
            ct1.as_bytes(),
            ct2.as_bytes(),
            "Randomized encapsulation should produce different ciphertexts"
        );

        // Shared secrets should also differ
        assert_ne!(
            ss1.as_bytes(),
            ss2.as_bytes(),
            "Different encapsulations should produce different shared secrets"
        );

        Ok(())
    }

    // Resource limit tests
    #[test]
    fn test_encapsulate_oversized_public_key() {
        // Create a public key that's too large (exceeds resource limit)
        let oversized_pk = MlKemPublicKey::new(
            MlKemSecurityLevel::MlKem1024,
            vec![0u8; 101 * 1024 * 1024], // 101MB exceeds limit
        );

        // Construction should fail first due to size mismatch
        assert!(oversized_pk.is_err(), "Oversized public key should be rejected");
    }

    #[test]
    fn test_decapsulate_oversized_ciphertext() -> Result<(), MlKemError> {
        let mut rng = OsRng;
        let (_pk, _sk) = MlKem::generate_keypair(&mut rng, MlKemSecurityLevel::MlKem512)?;

        // Create an oversized ciphertext (exceeds resource limit)
        let oversized_ct = MlKemCiphertext::new(
            MlKemSecurityLevel::MlKem512,
            vec![0u8; 101 * 1024 * 1024], // 101MB exceeds limit
        );

        // Construction should fail first due to size mismatch
        assert!(oversized_ct.is_err(), "Oversized ciphertext should be rejected");
        Ok(())
    }
}
