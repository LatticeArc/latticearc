#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

//! FN-DSA (Fast-Fourier Lattice-based Compact Signatures over NTRU) Implementation
//!
//! FN-DSA is a lattice-based digital signature algorithm based on the NTRU lattice
//! problem. It provides post-quantum security with smaller signatures than ML-DSA.
//!
//! This implementation wraps the official `fn-dsa` crate by Thomas Pornin.
//! FN-DSA is based on the Falcon signature scheme, which NIST selected for
//! standardization as FIPS 206. **As of this writing, FIPS 206 has not been
//! finalized** — Falcon remains in the standardization pipeline alongside the
//! already-published ML-KEM (FIPS 203), ML-DSA (FIPS 204), and SLH-DSA (FIPS
//! 205). Treat the algorithm as "draft FIPS 206 / Falcon" until NIST publishes
//! the final standard.
//!
//! Key features:
//! - Lattice-based security (NTRU Lattice hardness)
//! - Smaller signatures than ML-DSA (666 bytes vs ~2.4KB)
//! - Fast verification
//! - Integration with official `fn-dsa` crate
//!
//! Security Levels:
//! - FN-DSA-512: ~128-bit security (Level I)
//! - FN-DSA-1024: ~256-bit security (Level V)

use crate::prelude::error::LatticeArcError;
// `fn-dsa 0.3` is pinned to `rand_core 0.6`; use the 0.6 traits/types for the
// keygen and signing entry points. See workspace Cargo.toml `rand_core_0_6`.
use rand_core_0_6::OsRng;
use subtle::ConstantTimeEq;
use tracing::instrument;
use zeroize::{Zeroize, Zeroizing};

use fn_dsa::{
    DOMAIN_NONE, FN_DSA_LOGN_512, FN_DSA_LOGN_1024, HASH_ID_RAW, KeyPairGenerator as _,
    KeyPairGeneratorStandard, SigningKey as _, VerifyingKey as _, sign_key_size, signature_size,
    vrfy_key_size,
};

/// Errors returned by FN-DSA operations. Mirrors the per-module error pattern
/// used by [`crate::primitives::sig::ml_dsa::MlDsaError`] and
/// [`crate::primitives::sig::slh_dsa::SlhDsaError`].
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum FnDsaError {
    /// Key generation failed.
    #[error("Key generation failed: {0}")]
    KeyGenerationError(String),

    /// Key bytes have the wrong length for the declared security level.
    #[error("Invalid key length: expected {expected}, got {actual}")]
    InvalidKeyLength {
        /// Expected key size in bytes for the security level.
        expected: usize,
        /// Actual key size in bytes provided by the caller.
        actual: usize,
    },

    /// Key bytes are the correct length but failed to decode.
    #[error("Invalid key: {0}")]
    InvalidKey(String),

    /// Signature bytes are invalid (wrong length, malformed, or rejected by
    /// the upstream decoder).
    #[error("Invalid signature: {0}")]
    InvalidSignature(String),

    /// Message length exceeds the configured resource limit. Unit variant —
    /// length is known to the sender.
    #[error("Message exceeds signature resource limit")]
    MessageTooLong,
}

impl From<FnDsaError> for LatticeArcError {
    fn from(err: FnDsaError) -> Self {
        match err {
            FnDsaError::KeyGenerationError(msg) => Self::KeyGenerationError(msg),
            FnDsaError::InvalidKeyLength { expected, actual } => Self::InvalidKey(format!(
                "Invalid FN-DSA key length: expected {expected}, got {actual}",
            )),
            FnDsaError::InvalidKey(msg) => Self::InvalidKey(msg),
            FnDsaError::InvalidSignature(msg) => Self::InvalidSignature(msg),
            FnDsaError::MessageTooLong => Self::MessageTooLong,
        }
    }
}

/// Module-local Result alias for FN-DSA operations.
type Result<T> = std::result::Result<T, FnDsaError>;

/// FN-DSA security level
///
/// Defines the security parameters for FN-DSA (Few-Time Digital Signature Algorithm).
/// Based on the NTRU lattice problem with different security levels.
///
/// See [FIPS 206 (pending)](https://csrc.nist.gov/Projects/post-quantum-cryptography) for specifications.
///
/// # Security Levels
///
/// - **Level 512**: Approximately 128-bit security against quantum attacks
/// - **Level 1024**: Approximately 256-bit security against quantum attacks
///
/// # Selection Guidelines
///
/// Choose based on your security requirements and performance constraints:
/// - **Level 512**: Suitable for most applications with standard security needs
/// - **Level 1024**: For high-security applications requiring maximum protection
#[non_exhaustive]
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FnDsaSecurityLevel {
    /// FN-DSA-512 (~128-bit security)
    ///
    /// Provides security comparable to AES-128 in a post-quantum setting.
    /// This is the recommended default for most applications.
    #[default]
    Level512,
    /// FN-DSA-1024 (~256-bit security)
    ///
    /// Provides security comparable to AES-256 in a post-quantum setting.
    /// Use for high-security applications where maximum protection is required.
    Level1024,
}

impl FnDsaSecurityLevel {
    /// Returns the logn parameter for the underlying fn-dsa crate
    ///
    /// The `logn` parameter determines the degree of the NTRU lattice polynomial
    /// and is a key factor in security and performance.
    ///
    /// # Returns
    ///
    /// - `9` for Level 512 (FN-DSA-512)
    /// - `10` for Level 1024 (FN-DSA-1024)
    #[must_use]
    pub fn to_logn(&self) -> u32 {
        match self {
            FnDsaSecurityLevel::Level512 => FN_DSA_LOGN_512,
            FnDsaSecurityLevel::Level1024 => FN_DSA_LOGN_1024,
        }
    }

    /// Returns the signature size in bytes for this security level
    ///
    /// FN-DSA produces compact signatures, making it suitable for
    /// bandwidth-constrained environments.
    ///
    /// # Returns
    ///
    /// - `666` bytes for Level 512
    /// - `1280` bytes for Level 1024
    #[must_use]
    pub fn signature_size(&self) -> usize {
        signature_size(self.to_logn())
    }

    /// Returns the signing key (secret key) size in bytes for this security level
    ///
    /// # Returns
    ///
    /// - `1281` bytes for Level 512
    /// - `2305` bytes for Level 1024
    #[must_use]
    pub fn signing_key_size(&self) -> usize {
        sign_key_size(self.to_logn())
    }

    /// Returns the verifying key (public key) size in bytes for this security level
    ///
    /// # Returns
    ///
    /// - `897` bytes for Level 512
    /// - `1793` bytes for Level 1024
    #[must_use]
    pub fn verifying_key_size(&self) -> usize {
        vrfy_key_size(self.to_logn())
    }
}

/// FN-DSA signature
///
/// Represents a digital signature produced by the FN-DSA algorithm.
/// FN-DSA signatures are compact and fast to verify, making them
/// suitable for high-throughput applications.
///
/// # Security
///
/// Signatures provide EUF-CMA (Existential Unforgeability under
/// Chosen Message Attacks) security based on the hardness of the
/// NTRU lattice problem.
///
/// # Example
///
/// ```no_run
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use latticearc::primitives::sig::fndsa::{Signature, KeyPair, FnDsaSecurityLevel};
/// use rand_core_0_6::OsRng;
///
/// let mut rng = OsRng;
/// let mut keypair = KeyPair::generate_with_rng(&mut rng, FnDsaSecurityLevel::Level512)?;
/// let message = b"Important message";
///
/// let signature = keypair.sign_with_rng(&mut rng, message)?;
/// assert_eq!(signature.len(), 666); // FN-DSA-512 signature size
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature {
    /// Raw signature bytes
    /// Consumer: to_bytes(), as_ref(), len(), is_empty()
    bytes: Vec<u8>,
}

impl Signature {
    /// Create a signature from bytes
    ///
    /// # Errors
    /// Returns an error if the signature bytes are empty.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() {
            return Err(FnDsaError::InvalidSignature(
                "Signature bytes cannot be empty".to_string(),
            ));
        }
        Ok(Self { bytes: bytes.to_vec() })
    }

    /// Borrow the raw signature bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Copy the signature bytes into an owned vector.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    /// Get signature length
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Check if signature is empty
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl TryFrom<Vec<u8>> for Signature {
    type Error = FnDsaError;
    fn try_from(bytes: Vec<u8>) -> std::result::Result<Self, Self::Error> {
        Self::from_bytes(&bytes)
    }
}

/// FN-DSA verifying key (public key)
///
/// Contains the public key material for verifying FN-DSA signatures.
/// Verifying keys can be freely distributed and are used to
/// authenticate signatures without access to the signing key.
///
/// # Security
///
/// Public keys do not need to be kept secret. They can be
/// shared openly for signature verification.
///
/// # Format
///
/// The key is encoded in the format specified by draft FIPS 206.
///
/// # Example
///
/// ```no_run
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use latticearc::primitives::sig::fndsa::{VerifyingKey, KeyPair, FnDsaSecurityLevel};
/// use rand_core_0_6::OsRng;
///
/// let mut rng = OsRng;
/// let mut keypair = KeyPair::generate_with_rng(&mut rng, FnDsaSecurityLevel::Level512)?;
/// # let message = b"test";
/// # let signature = keypair.sign_with_rng(&mut rng, message)?;
///
/// // Export verifying key for distribution
/// let vk_bytes = keypair.verifying_key().to_bytes();
/// let vk_restored = VerifyingKey::from_bytes(&vk_bytes, FnDsaSecurityLevel::Level512)?;
///
/// // Verify a signature
/// let is_valid = vk_restored.verify(message, &signature)?;
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug)]
pub struct VerifyingKey {
    /// Security level associated with this key
    security_level: FnDsaSecurityLevel,
    /// Internal verifying key from fn-dsa crate
    inner: FnDsaVerifyingKeyStandard,
    /// Serialized key bytes for export/storage
    bytes: Vec<u8>,
}

impl VerifyingKey {
    /// Get the security level of this verifying key
    #[must_use]
    pub fn security_level(&self) -> FnDsaSecurityLevel {
        self.security_level
    }

    /// Create verifying key from bytes
    ///
    /// # Errors
    /// Returns an error if the key length is incorrect or decoding fails.
    pub fn from_bytes(bytes: &[u8], security_level: FnDsaSecurityLevel) -> Result<Self> {
        if bytes.len() != security_level.verifying_key_size() {
            return Err(FnDsaError::InvalidKeyLength {
                expected: security_level.verifying_key_size(),
                actual: bytes.len(),
            });
        }

        let inner = FnDsaVerifyingKeyStandard::decode(bytes)
            .ok_or_else(|| FnDsaError::InvalidKey("Failed to decode verifying key".to_string()))?;
        Ok(Self { security_level, inner, bytes: bytes.to_vec() })
    }

    /// Borrow the raw verifying key bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Copy the verifying key bytes into an owned vector.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    /// Verify a signature.
    ///
    /// Returns `Ok(true)` if the signature is valid, `Ok(false)` otherwise.
    ///
    /// # Errors
    ///
    /// Currently infallible — the inner `fn-dsa` crate treats malformed
    /// signatures as `Ok(false)` rather than surfacing parse errors. The
    /// `Result` wrapper is retained for return-type parity with ML-DSA and
    /// SLH-DSA, and to keep future error paths (length pre-checks, HSM
    /// backends) a non-breaking addition.
    #[instrument(level = "debug", skip(self, message, signature), fields(security_level = ?self.security_level, message_len = message.len(), signature_len = signature.len()))]
    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<bool> {
        // DoS bound on the verify hot path. The fn-dsa crate hashes the
        // entire message during verification; without this guard a caller
        // can submit arbitrary-length input through any verify entry
        // point. Mirrors the bound applied in `sign_with_rng()`. The
        // size-limit error is folded into `LatticeArcError` (the public
        // Result type) via the existing `From<FnDsaError>` impl.
        // Round-26 audit fix (M1): collapse to opaque verification
        // failure on verify so a probing attacker cannot binary-search
        // the configured cap from the Result shape.
        if let Err(e) = crate::primitives::resource_limits::validate_signature_size(message.len()) {
            tracing::debug!(error = ?e, msg_len = message.len(), "FN-DSA verify rejected: message exceeds resource limit");
            return Ok(false);
        }

        let valid = self.inner.verify(signature.as_ref(), &DOMAIN_NONE, &HASH_ID_RAW, message);
        Ok(valid)
    }
}

/// FN-DSA signing key (secret key)
///
/// Contains private key material for generating FN-DSA signatures.
/// Signing keys must be kept secret and protected from unauthorized access.
///
/// # Security
///
/// - **Never expose**: Signing keys must never be shared or transmitted
/// - **Secure storage**: Store in hardware security modules or encrypted at rest
/// - **Zeroization**: Key data is automatically zeroized when dropped
///
/// # State Considerations
///
/// FN-DSA is a "few-time" signature scheme. While more flexible than
/// stateful schemes like LMS, it has limitations on how many signatures
/// can be safely made. See draft FIPS 206 for specific guidance.
///
/// # Example
///
/// ```no_run
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use latticearc::primitives::sig::fndsa::{SigningKey, KeyPair, FnDsaSecurityLevel};
/// use rand_core_0_6::OsRng;
///
/// let mut rng = OsRng;
/// let keypair = KeyPair::generate_with_rng(&mut rng, FnDsaSecurityLevel::Level512)?;
///
/// // Signing key provides access to verification key
/// let vk = keypair.signing_key().verifying_key();
/// # Ok(())
/// # }
/// ```
///
/// # Zeroization
///
/// Both the serialized `bytes` field and the inner `FnDsaSigningKeyStandard`
/// are zeroized on drop. The `fn-dsa` crate (v0.3.0+) derives `Zeroize` and
/// `ZeroizeOnDrop` on `SigningKeyStandard`, so inner key material is wiped
/// when this struct drops or when `zeroize()` is called explicitly.
pub struct SigningKey {
    /// Security level for this key
    security_level: FnDsaSecurityLevel,
    /// Internal signing key from fn-dsa crate (zeroized on drop)
    inner: FnDsaSigningKeyStandard,
    /// Serialized key bytes for secure storage (zeroized on drop)
    bytes: Vec<u8>,
    /// Associated verifying key (public key)
    verifying_key: VerifyingKey,
}

impl Drop for SigningKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl Zeroize for SigningKey {
    fn zeroize(&mut self) {
        self.inner.zeroize();
        // Zero each byte in-place to preserve Vec length (Vec::zeroize truncates).
        // Tests assert length is preserved after explicit zeroize().
        for byte in &mut self.bytes {
            byte.zeroize();
        }
    }
}

impl std::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigningKey").field("has_inner", &true).finish()
    }
}

impl ConstantTimeEq for SigningKey {
    /// Constant-time comparison of signing key bytes.
    ///
    /// The security level and length must match; the byte content is compared
    /// in constant time to prevent timing side-channels.
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        let level_eq = (self.security_level as u8).ct_eq(&(other.security_level as u8));
        // ct_eq on slices of different length returns Choice::from(0)
        level_eq & self.bytes.ct_eq(&other.bytes)
    }
}

impl SigningKey {
    /// Create signing key from bytes
    ///
    /// # Errors
    /// Returns an error if the key length is incorrect or decoding fails.
    pub fn from_bytes(bytes: &[u8], security_level: FnDsaSecurityLevel) -> Result<Self> {
        if bytes.len() != security_level.signing_key_size() {
            return Err(FnDsaError::InvalidKeyLength {
                expected: security_level.signing_key_size(),
                actual: bytes.len(),
            });
        }
        let inner = FnDsaSigningKeyStandard::decode(bytes)
            .ok_or_else(|| FnDsaError::InvalidKey("Failed to decode signing key".to_string()))?;

        // Extract verifying key from signing key
        let mut vrfy_key_bytes = vec![0u8; security_level.verifying_key_size()];
        inner.to_verifying_key(&mut vrfy_key_bytes);
        let verifying_key = VerifyingKey::from_bytes(&vrfy_key_bytes, security_level)?;

        Ok(Self { security_level, inner, bytes: bytes.to_vec(), verifying_key })
    }

    /// Expose the signing key bytes.
    ///
    /// Sealed accessor per Secret Type Invariant I-8
    /// (`docs/SECRET_TYPE_INVARIANTS.md`). The returned slice aliases
    /// internal key material that will be zeroized on drop of `self`; do not
    /// persist or copy it without using a zeroizing container.
    #[must_use]
    pub fn expose_secret(&self) -> &[u8] {
        &self.bytes
    }

    /// Copy the signing key bytes into a zeroizing owned buffer.
    ///
    /// Returns `Zeroizing<Vec<u8>>` to ensure the secret key bytes are zeroized on drop.
    #[must_use]
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.bytes.clone())
    }

    /// Get the verifying key
    #[must_use]
    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }

    /// Get the security level of this signing key
    #[must_use]
    pub fn security_level(&self) -> FnDsaSecurityLevel {
        self.security_level
    }

    /// Sign a message using the OS CSPRNG ([`rand::rngs::OsRng`]).
    ///
    /// This is the recommended form for production signing. For deterministic
    /// signing with a seeded RNG (e.g. KAT validation), use
    /// [`SigningKey::sign_with_rng`].
    ///
    /// # Errors
    /// Returns an error if signature encoding fails.
    #[instrument(level = "debug", skip(self, message), fields(security_level = ?self.security_level, message_len = message.len()))]
    pub fn sign(&mut self, message: &[u8]) -> Result<Signature> {
        self.sign_with_rng(&mut OsRng, message)
    }

    /// Sign a message using a caller-supplied CSPRNG.
    ///
    /// # Errors
    /// Returns an error if signature encoding fails.
    #[instrument(level = "debug", skip(self, rng, message), fields(security_level = ?self.security_level, message_len = message.len()))]
    pub fn sign_with_rng<R: rand_core_0_6::RngCore + rand_core_0_6::CryptoRng>(
        &mut self,
        rng: &mut R,
        message: &[u8],
    ) -> Result<Signature> {
        // DoS bound: primitive callers bypass unified_api's resource limits.
        crate::primitives::resource_limits::validate_signature_size(message.len())
            .map_err(|_e| FnDsaError::MessageTooLong)?;

        let logn = match self.security_level {
            FnDsaSecurityLevel::Level512 => FN_DSA_LOGN_512,
            FnDsaSecurityLevel::Level1024 => FN_DSA_LOGN_1024,
        };
        // sig_bytes is an intermediate signing buffer; FN-DSA signatures
        // expose lattice nonce information, so wipe on drop.
        let mut sig_bytes = Zeroizing::new(vec![0u8; signature_size(logn)]);
        self.inner.sign(rng, &DOMAIN_NONE, &HASH_ID_RAW, message, &mut sig_bytes);
        Signature::from_bytes(&sig_bytes)
    }
}

/// FN-DSA keypair
///
/// Contains both signing key (secret) and verifying key (public) for FN-DSA.
/// Provides a convenient interface for key generation and signing operations.
///
/// # Usage
///
/// ```no_run
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use latticearc::primitives::sig::fndsa::{KeyPair, FnDsaSecurityLevel};
/// use rand_core_0_6::OsRng;
///
/// let mut rng = OsRng;
/// let mut keypair = KeyPair::generate_with_rng(&mut rng, FnDsaSecurityLevel::Level512)?;
///
/// // Sign a message
/// let message = b"Important data";
/// let signature = keypair.sign_with_rng(&mut rng, message)?;
///
/// // Verify the signature
/// let is_valid = keypair.verify(message, &signature)?;
/// assert!(is_valid);
///
/// // Export keys for storage/distribution
/// let sk_bytes = keypair.signing_key().to_bytes();
/// let vk_bytes = keypair.verifying_key().to_bytes();
/// # Ok(())
/// # }
/// ```
///
/// # Security
///
/// - The signing key component must be kept secret
/// - The verifying key component can be freely distributed
/// - Both keys are encoded according to draft FIPS 206
/// - Signing key material is zeroized on drop (both serialized bytes and inner state)
pub struct KeyPair {
    /// Secret signing key component
    signing_key: SigningKey,
    /// Public verifying key component
    verifying_key: VerifyingKey,
}

impl std::fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyPair")
            .field("signing_key", &"[REDACTED]")
            .field("verifying_key", &"[public]")
            .finish()
    }
}

impl Drop for KeyPair {
    fn drop(&mut self) {
        // Zeroize the signing key (delegates to SigningKey's Zeroize impl)
        self.signing_key.zeroize();
    }
}

impl ConstantTimeEq for KeyPair {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.signing_key.ct_eq(&other.signing_key)
    }
}

impl Zeroize for KeyPair {
    fn zeroize(&mut self) {
        self.signing_key.zeroize();
        // verifying_key is public data, no need to zeroize
    }
}

impl KeyPair {
    /// Generate a new FN-DSA keypair using the OS CSPRNG ([`rand::rngs::OsRng`]).
    ///
    /// This is the recommended way to produce key material for non-deterministic
    /// use cases. For deterministic testing, pass a seeded RNG via
    /// [`KeyPair::generate_with_rng`].
    ///
    /// Key generation follows the specification in
    /// [draft FIPS 206](https://csrc.nist.gov/Projects/post-quantum-cryptography).
    /// After key generation, a FIPS 140-3 Pairwise Consistency Test (PCT)
    /// is performed to verify the keypair is valid.
    ///
    /// # Errors
    ///
    /// Returns an error if the `fn_dsa` feature is not enabled, if
    /// key generation fails (e.g., RNG failure), or if the PCT fails.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// use latticearc::primitives::sig::fndsa::{KeyPair, FnDsaSecurityLevel};
    ///
    /// let keypair = KeyPair::generate(FnDsaSecurityLevel::Level512)?;
    /// println!("Public key: {} bytes", keypair.verifying_key().to_bytes().len());
    /// # Ok(())
    /// # }
    /// ```
    #[instrument(level = "debug", fields(security_level = ?security_level))]
    pub fn generate(security_level: FnDsaSecurityLevel) -> Result<Self> {
        Self::generate_with_rng(&mut OsRng, security_level)
    }

    /// Generate a new FN-DSA keypair using a caller-supplied CSPRNG.
    ///
    /// Use this form when you need deterministic key generation (seeded RNG)
    /// for tests or KAT validation.
    ///
    /// # Errors
    /// Returns an error if the backend keygen or FIPS 140-3 PCT fails.
    #[instrument(level = "debug", skip(rng), fields(security_level = ?security_level))]
    pub fn generate_with_rng<R: rand_core_0_6::RngCore + rand_core_0_6::CryptoRng>(
        rng: &mut R,
        security_level: FnDsaSecurityLevel,
    ) -> Result<Self> {
        let mut kg = KeyPairGeneratorStandard::default();
        let logn = security_level.to_logn();

        let mut sk_bytes = Zeroizing::new(vec![0u8; sign_key_size(logn)]);
        let mut vk_bytes = vec![0u8; vrfy_key_size(logn)];

        kg.keygen(logn, rng, &mut sk_bytes, &mut vk_bytes);

        let signing_key = SigningKey::from_bytes(&sk_bytes, security_level)?;
        let verifying_key = VerifyingKey::from_bytes(&vk_bytes, security_level)?;

        let mut keypair = Self { signing_key, verifying_key };

        // FIPS 140-3 Pairwise Consistency Test (PCT)
        // Sign and verify a test message to ensure the keypair is consistent
        crate::primitives::pct::pct_fn_dsa_keypair(&mut keypair)
            .map_err(|e| FnDsaError::KeyGenerationError(format!("PCT failed: {}", e)))?;

        Ok(keypair)
    }

    /// Get the signing key
    #[must_use]
    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }

    /// Get the verifying key
    #[must_use]
    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }

    /// Sign a message using the OS CSPRNG ([`rand::rngs::OsRng`]).
    ///
    /// This is the recommended form for production signing. For deterministic
    /// signing with a seeded RNG (KAT validation), use
    /// [`KeyPair::sign_with_rng`].
    ///
    /// # Errors
    /// Returns an error if signature encoding fails.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// use latticearc::primitives::sig::fndsa::{KeyPair, FnDsaSecurityLevel};
    ///
    /// let mut keypair = KeyPair::generate(FnDsaSecurityLevel::Level512)?;
    ///
    /// let message = b"Critical transaction data";
    /// let signature = keypair.sign(message)?;
    ///
    /// let is_valid = keypair.verify(message, &signature)?;
    /// assert!(is_valid);
    /// # Ok(())
    /// # }
    /// ```
    pub fn sign(&mut self, message: &[u8]) -> Result<Signature> {
        self.signing_key.sign(message)
    }

    /// Sign a message using a caller-supplied CSPRNG.
    ///
    /// Use this for deterministic signing with a seeded RNG (e.g., KAT tests).
    ///
    /// # Errors
    /// Returns an error if signature encoding fails.
    pub fn sign_with_rng<R: rand_core_0_6::RngCore + rand_core_0_6::CryptoRng>(
        &mut self,
        rng: &mut R,
        message: &[u8],
    ) -> Result<Signature> {
        self.signing_key.sign_with_rng(rng, message)
    }

    /// Verifies a signature against a message using the verifying key
    ///
    /// This function checks whether the provided signature was validly created
    /// for the given message using the signing key that corresponds to this
    /// verifying key.
    ///
    /// # Arguments
    ///
    /// * `message` - The message that was signed
    /// * `signature` - The signature to verify
    ///
    /// # Returns
    ///
    /// - `Ok(true)` - Signature is valid for this message
    /// - `Ok(false)` - Signature is invalid or for a different message
    /// - `Err(_)` - Verification operation failed (e.g., malformed inputs)
    ///
    /// # Security
    ///
    /// - Verification is constant-time to prevent timing attacks
    /// - Does not require secret key material
    /// - Correctly rejects forged signatures
    ///
    /// # Errors
    /// Returns an error if the fn_dsa feature is not enabled.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// use latticearc::primitives::sig::fndsa::{KeyPair, FnDsaSecurityLevel};
    /// use rand_core_0_6::OsRng;
    ///
    /// let mut rng = OsRng;
    /// let mut keypair = KeyPair::generate_with_rng(&mut rng, FnDsaSecurityLevel::Level512)?;
    ///
    /// let message = b"Important document";
    /// let signature = keypair.sign_with_rng(&mut rng, message)?;
    ///
    /// // Verify valid signature
    /// let is_valid = keypair.verify(message, &signature)?;
    /// assert!(is_valid);
    ///
    /// // Reject invalid message
    /// let wrong_message = b"Tampered message";
    /// let is_valid = keypair.verify(wrong_message, &signature)?;
    /// assert!(!is_valid);
    /// # Ok(())
    /// # }
    /// ```
    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<bool> {
        self.verifying_key.verify(message, signature)
    }
}

// Type aliases for convenience

/// FN-DSA signing key using the standard format
pub(crate) type FnDsaSigningKeyStandard = fn_dsa::SigningKeyStandard;
/// FN-DSA verifying key using the standard format
pub(crate) type FnDsaVerifyingKeyStandard = fn_dsa::VerifyingKeyStandard;

#[cfg(test)]
#[allow(clippy::unwrap_used)] // Tests use unwrap for simplicity
#[allow(clippy::expect_used)] // Tests use expect for simplicity
mod tests {
    use super::*;
    use rand_core_0_6::OsRng;

    #[test]
    fn test_fndsa_key_generation_512_succeeds() {
        std::thread::Builder::new()
            .stack_size(32 * 1024 * 1024)
            .spawn(|| {
                let mut rng = OsRng;
                let keypair =
                    KeyPair::generate_with_rng(&mut rng, FnDsaSecurityLevel::Level512).unwrap();

                assert_eq!(
                    keypair.signing_key().to_bytes().len(),
                    FnDsaSecurityLevel::Level512.signing_key_size()
                );
                assert_eq!(
                    keypair.verifying_key().to_bytes().len(),
                    FnDsaSecurityLevel::Level512.verifying_key_size()
                );
            })
            .expect("Thread spawn failed")
            .join()
            .expect("Thread join failed");
    }

    #[test]
    fn test_fndsa_key_generation_1024_succeeds() {
        std::thread::Builder::new()
            .stack_size(32 * 1024 * 1024)
            .spawn(|| {
                let mut rng = OsRng;
                let keypair =
                    KeyPair::generate_with_rng(&mut rng, FnDsaSecurityLevel::Level1024).unwrap();

                assert_eq!(
                    keypair.signing_key().to_bytes().len(),
                    FnDsaSecurityLevel::Level1024.signing_key_size()
                );
                assert_eq!(
                    keypair.verifying_key().to_bytes().len(),
                    FnDsaSecurityLevel::Level1024.verifying_key_size()
                );
            })
            .expect("Thread spawn failed")
            .join()
            .expect("Thread join failed");
    }

    #[test]
    fn test_fndsa_signature_sign_verify_roundtrip() {
        std::thread::Builder::new()
            .stack_size(32 * 1024 * 1024)
            .spawn(|| {
                let mut rng = OsRng;
                let mut keypair =
                    KeyPair::generate_with_rng(&mut rng, FnDsaSecurityLevel::Level512).unwrap();
                let message = b"Hello, FN-DSA world!";

                let mut rng = OsRng;
                let signature = keypair.sign_with_rng(&mut rng, message).unwrap();
                let verified = keypair.verify(message, &signature).unwrap();
                assert!(verified);
            })
            .expect("Thread spawn failed")
            .join()
            .expect("Thread join failed");
    }

    #[test]
    fn test_fndsa_wrong_message_fails() {
        std::thread::Builder::new()
            .stack_size(32 * 1024 * 1024)
            .spawn(|| {
                let mut rng = OsRng;
                let mut keypair =
                    KeyPair::generate_with_rng(&mut rng, FnDsaSecurityLevel::Level512).unwrap();
                let message = b"Correct message";
                let wrong_message = b"Wrong message";

                let mut rng = OsRng;
                let signature = keypair.sign_with_rng(&mut rng, message).unwrap();
                let verified = keypair.verify(wrong_message, &signature).unwrap();
                assert!(!verified);
            })
            .expect("Thread spawn failed")
            .join()
            .expect("Thread join failed");
    }

    #[test]
    fn test_fndsa_key_serialization_roundtrip() {
        std::thread::Builder::new()
            .stack_size(32 * 1024 * 1024)
            .spawn(|| {
                let mut rng = OsRng;
                let keypair =
                    KeyPair::generate_with_rng(&mut rng, FnDsaSecurityLevel::Level512).unwrap();

                // Serialize/deserialize signing key
                let sk_bytes = keypair.signing_key().to_bytes();
                let deserialized_sk =
                    SigningKey::from_bytes(&sk_bytes, FnDsaSecurityLevel::Level512).unwrap();
                assert_eq!(keypair.signing_key().to_bytes(), deserialized_sk.to_bytes());

                // Serialize/deserialize verifying key
                let vk_bytes = keypair.verifying_key().to_bytes();
                let deserialized_vk =
                    VerifyingKey::from_bytes(&vk_bytes, FnDsaSecurityLevel::Level512).unwrap();
                assert_eq!(keypair.verifying_key().to_bytes(), deserialized_vk.to_bytes());
            })
            .expect("Thread spawn failed")
            .join()
            .expect("Thread join failed");
    }

    #[test]
    fn test_fndsa_signature_serialization_roundtrip() {
        std::thread::Builder::new()
            .stack_size(32 * 1024 * 1024)
            .spawn(|| {
                let mut rng = OsRng;
                let mut keypair =
                    KeyPair::generate_with_rng(&mut rng, FnDsaSecurityLevel::Level512).unwrap();
                let message = b"Test message";
                let mut rng = OsRng;
                let signature = keypair.sign_with_rng(&mut rng, message).unwrap();

                let sig_bytes = signature.to_bytes();
                let deserialized_sig = Signature::from_bytes(&sig_bytes).unwrap();
                assert_eq!(signature.to_bytes(), deserialized_sig.to_bytes());
            })
            .expect("Thread spawn failed")
            .join()
            .expect("Thread join failed");
    }

    #[test]
    fn test_fndsa_security_level_sizes_match_spec_has_correct_size() {
        let level512 = FnDsaSecurityLevel::Level512;
        let level1024 = FnDsaSecurityLevel::Level1024;

        assert_eq!(level512.signature_size(), 666);
        assert_eq!(level512.signing_key_size(), 1281);
        assert_eq!(level512.verifying_key_size(), 897);

        assert_eq!(level1024.signature_size(), 1280);
        assert_eq!(level1024.signing_key_size(), 2305);
        assert_eq!(level1024.verifying_key_size(), 1793);
    }

    #[test]
    fn test_fndsa_empty_signature_is_rejected() {
        let result = Signature::from_bytes(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_fndsa_invalid_key_length_is_rejected() {
        let result = VerifyingKey::from_bytes(&[0u8; 100], FnDsaSecurityLevel::Level512);
        assert!(result.is_err());

        let result = SigningKey::from_bytes(&[0u8; 100], FnDsaSecurityLevel::Level512);
        assert!(result.is_err());
    }

    #[test]
    fn test_fndsa_security_level_default_is_level512_succeeds() {
        let level = FnDsaSecurityLevel::default();
        assert_eq!(level, FnDsaSecurityLevel::Level512);
    }

    #[test]
    fn test_fndsa_security_level_to_logn_matches_spec_succeeds() {
        assert_eq!(FnDsaSecurityLevel::Level512.to_logn(), FN_DSA_LOGN_512);
        assert_eq!(FnDsaSecurityLevel::Level1024.to_logn(), FN_DSA_LOGN_1024);
    }

    /// Test that verifies the key_bytes field is properly zeroized when the signing key
    /// is dropped or explicitly zeroized.
    ///
    /// # Security Note
    ///
    /// This test verifies zeroization of the serialized `bytes` field. The inner
    /// `FnDsaSigningKeyStandard` is also zeroized (fn-dsa v0.3.0+ derives Zeroize),
    /// but its internal state is not exposed for direct byte-level verification.
    #[test]
    fn test_fndsa_signing_key_zeroization_clears_bytes_succeeds() {
        std::thread::Builder::new()
            .stack_size(32 * 1024 * 1024)
            .spawn(|| {
                // Create a signing key directly from bytes to avoid KeyPair's Drop constraint
                let mut rng = OsRng;
                let keypair =
                    KeyPair::generate_with_rng(&mut rng, FnDsaSecurityLevel::Level512).unwrap();
                let sk_bytes = keypair.signing_key().to_bytes();
                drop(keypair);

                // Create a new signing key from the bytes
                let mut signing_key =
                    SigningKey::from_bytes(&sk_bytes, FnDsaSecurityLevel::Level512).unwrap();

                // Store the original key bytes for comparison
                let original_bytes = signing_key.to_bytes();
                let key_len = original_bytes.len();

                // Verify the key has non-zero content before zeroization
                assert!(
                    original_bytes.iter().any(|&b| b != 0),
                    "Key bytes should not be all zeros before zeroization"
                );

                // Explicitly zeroize the key
                signing_key.zeroize();

                // Verify the internal bytes field is now zeroed
                // Note: to_bytes() returns a clone of the internal bytes field
                let zeroized_bytes = signing_key.to_bytes();
                assert_eq!(
                    zeroized_bytes.len(),
                    key_len,
                    "Key bytes length should remain unchanged after zeroization"
                );
                assert!(
                    zeroized_bytes.iter().all(|&b| b == 0),
                    "Key bytes should be all zeros after zeroization"
                );
            })
            .expect("Thread spawn failed")
            .join()
            .expect("Thread join failed");
    }

    /// Test that KeyPair properly zeroizes its signing key on drop.
    #[test]
    fn test_fndsa_keypair_zeroization_clears_bytes_succeeds() {
        std::thread::Builder::new()
            .stack_size(32 * 1024 * 1024)
            .spawn(|| {
                let mut rng = OsRng;
                let mut keypair =
                    KeyPair::generate_with_rng(&mut rng, FnDsaSecurityLevel::Level512).unwrap();

                // Store the original key bytes for comparison
                let original_bytes = keypair.signing_key().to_bytes();

                // Verify the key has non-zero content
                assert!(
                    original_bytes.iter().any(|&b| b != 0),
                    "Key bytes should not be all zeros"
                );

                // Explicitly zeroize the keypair
                keypair.zeroize();

                // Verify the signing key's bytes are now zeroed
                let zeroized_bytes = keypair.signing_key().to_bytes();
                assert!(
                    zeroized_bytes.iter().all(|&b| b == 0),
                    "Key bytes should be all zeros after zeroization"
                );
            })
            .expect("Thread spawn failed")
            .join()
            .expect("Thread join failed");
    }

    /// Round-27 H5 (Pattern 14): the `MessageTooLong` variant must be
    /// triggerable through the public sign path. Default global cap is
    /// 64 KiB; pass 64 KiB + 1 to exceed it before the upstream
    /// `fn-dsa` signer runs. FN-DSA uses a stack-heavy signer so the
    /// test runs on a worker thread (matching the rest of this file).
    #[test]
    fn test_fndsa_sign_oversized_message_returns_message_too_long() {
        std::thread::Builder::new()
            .stack_size(32 * 1024 * 1024)
            .spawn(|| {
                let mut rng = OsRng;
                let mut keypair =
                    KeyPair::generate_with_rng(&mut rng, FnDsaSecurityLevel::Level512)
                        .expect("Key generation failed");
                let oversize: Vec<u8> = vec![0u8; (64 * 1024) + 1];
                let err = keypair.sign(&oversize).expect_err("oversized message must be rejected");
                assert!(
                    matches!(err, FnDsaError::MessageTooLong),
                    "expected MessageTooLong, got {err:?}"
                );
            })
            .expect("Thread spawn failed")
            .join()
            .expect("Thread join failed");
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)] // Tests use unwrap for simplicity
#[allow(clippy::expect_used)] // Tests use expect for simplicity
mod integration_tests {
    use super::*;
    use rand_core_0_6::OsRng;

    #[test]
    fn test_fndsa_multiple_messages_same_key_all_verify_succeeds() {
        std::thread::Builder::new()
            .stack_size(32 * 1024 * 1024)
            .spawn(|| {
                let mut rng = OsRng;
                let mut keypair =
                    KeyPair::generate_with_rng(&mut rng, FnDsaSecurityLevel::Level512).unwrap();

                let message1 = b"Message 1";
                let message2 = b"Message 2";

                let mut rng = OsRng;
                let sig1 = keypair.sign_with_rng(&mut rng, message1).unwrap();
                let mut rng = OsRng;
                let sig2 = keypair.sign_with_rng(&mut rng, message2).unwrap();

                // Verify each signature with its message
                assert!(keypair.verify(message1, &sig1).unwrap());
                assert!(keypair.verify(message2, &sig2).unwrap());

                // Cross-verify should fail
                assert!(!keypair.verify(message2, &sig1).unwrap());
                assert!(!keypair.verify(message1, &sig2).unwrap());
            })
            .expect("Thread spawn failed")
            .join()
            .expect("Thread join failed");
    }

    #[test]
    fn test_fndsa_level1024_signature_sign_verify_roundtrip() {
        std::thread::Builder::new()
            .stack_size(32 * 1024 * 1024)
            .spawn(|| {
                let mut rng = OsRng;
                let mut keypair =
                    KeyPair::generate_with_rng(&mut rng, FnDsaSecurityLevel::Level1024).unwrap();
                let message = b"Test message for FN-DSA-1024";

                let mut rng = OsRng;
                let signature = keypair.sign_with_rng(&mut rng, message).unwrap();
                assert_eq!(signature.len(), 1280);

                let verified = keypair.verify(message, &signature).unwrap();
                assert!(verified);
            })
            .expect("Thread spawn failed")
            .join()
            .expect("Thread join failed");
    }
}
