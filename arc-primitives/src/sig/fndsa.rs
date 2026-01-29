#![deny(unsafe_code)]
#![warn(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

//! FIPS 206: FN-DSA (Few-Time Digital Signature Algorithm) Implementation
//!
//! FN-DSA is a lattice-based digital signature algorithm based on the NTRU Lattice
//! problem. It provides post-quantum security with smaller signatures than ML-DSA.
//!
//! This implementation wraps the official `fn-dsa` crate by Thomas Pornin.
//! FN-DSA is based on the FALCON signature scheme selected by NIST.
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

use arc_prelude::error::{LatticeArcError, Result};
use rand_core::RngCore;
use tracing::instrument;
use zeroize::Zeroize;

use fn_dsa::{
    DOMAIN_NONE, FN_DSA_LOGN_512, FN_DSA_LOGN_1024, HASH_ID_RAW, KeyPairGenerator as _,
    KeyPairGeneratorStandard, SigningKey as _, VerifyingKey as _, sign_key_size, signature_size,
    vrfy_key_size,
};

/// FN-DSA security level
///
/// Defines the security parameters for FN-DSA (Few-Time Digital Signature Algorithm).
/// Based on the NTRU lattice problem with different security levels.
///
/// See [FIPS 206](https://csrc.nist.gov/pubs/fips/206/final/) for specifications.
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FNDsaSecurityLevel {
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

impl FNDsaSecurityLevel {
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
            FNDsaSecurityLevel::Level512 => FN_DSA_LOGN_512,
            FNDsaSecurityLevel::Level1024 => FN_DSA_LOGN_1024,
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
/// ```ignore
/// use arc_primitives::sig::fndsa::{Signature, KeyPair, FNDsaSecurityLevel};
/// use rand::rngs::OsRng;
///
/// let mut rng = OsRng;
/// let mut keypair = KeyPair::generate(&mut rng, FNDsaSecurityLevel::Level512)?;
/// let message = b"Important message";
///
/// let signature = keypair.sign(&mut rng, message)?;
/// assert_eq!(signature.len(), 666); // FN-DSA-512 signature size
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature {
    /// Raw signature bytes
    pub bytes: Vec<u8>,
}

impl Signature {
    /// Create a signature from bytes
    ///
    /// # Errors
    /// Returns an error if the signature bytes are empty.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self> {
        if bytes.is_empty() {
            return Err(LatticeArcError::InvalidSignature(
                "Signature bytes cannot be empty".to_string(),
            ));
        }
        Ok(Self { bytes })
    }

    /// Convert signature to bytes
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

impl From<Vec<u8>> for Signature {
    fn from(bytes: Vec<u8>) -> Self {
        Self { bytes }
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
/// The key is encoded in the format specified by FIPS 206.
///
/// # Example
///
/// ```ignore
/// use arc_primitives::sig::fndsa::{VerifyingKey, KeyPair, FNDsaSecurityLevel};
/// use rand::rngs::OsRng;
///
/// let mut rng = OsRng;
/// let keypair = KeyPair::generate(&mut rng, FNDsaSecurityLevel::Level512)?;
///
/// // Export verifying key for distribution
/// let vk_bytes = keypair.verifying_key().to_bytes();
/// let vk_restored = VerifyingKey::from_bytes(vk_bytes, FNDsaSecurityLevel::Level512)?;
///
/// // Verify a signature
/// let is_valid = vk_restored.verify(message, &signature)?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Clone, Debug)]
pub struct VerifyingKey {
    /// Security level associated with this key
    security_level: FNDsaSecurityLevel,
    /// Internal verifying key from fn-dsa crate
    inner: FnDsaVerifyingKeyStandard,
    /// Serialized key bytes for export/storage
    bytes: Vec<u8>,
}

impl VerifyingKey {
    /// Get the security level of this verifying key
    #[must_use]
    pub fn security_level(&self) -> FNDsaSecurityLevel {
        self.security_level
    }

    /// Create verifying key from bytes
    ///
    /// # Errors
    /// Returns an error if the key length is incorrect or decoding fails.
    pub fn from_bytes(bytes: Vec<u8>, security_level: FNDsaSecurityLevel) -> Result<Self> {
        if bytes.len() != security_level.verifying_key_size() {
            return Err(LatticeArcError::InvalidKey("Invalid verifying key length".to_string()));
        }

        {
            Ok(Self {
                security_level,
                inner: FnDsaVerifyingKeyStandard::decode(&bytes).ok_or_else(|| {
                    LatticeArcError::InvalidKey("Failed to decode verifying key".to_string())
                })?,
                bytes,
            })
        }
    }

    /// Convert signing key to bytes
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    /// Verify a signature
    ///
    /// # Errors
    /// Returns an error if the fn_dsa feature is not enabled.
    #[instrument(level = "debug", skip(self, message, signature), fields(security_level = ?self.security_level, message_len = message.len(), signature_len = signature.len()))]
    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<bool> {
        {
            let valid = self.inner.verify(&signature.bytes, &DOMAIN_NONE, &HASH_ID_RAW, message);
            Ok(valid)
        }
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
/// can be safely made. See FIPS 206 for specific guidance.
///
/// # Example
///
/// ```ignore
/// use arc_primitives::sig::fndsa::{SigningKey, KeyPair, FNDsaSecurityLevel};
/// use rand::rngs::OsRng;
///
/// let mut rng = OsRng;
/// let keypair = KeyPair::generate(&mut rng, FNDsaSecurityLevel::Level512)?;
///
/// // Signing key provides access to verification key
/// let vk = keypair.signing_key().verifying_key();
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
///
/// # Security Note - Zeroization Limitations
///
/// The underlying `fn-dsa` crate does not implement `Zeroize` on its key types.
/// This wrapper stores a copy of the serialized key bytes which ARE zeroized on drop.
/// However, the inner key structure (`FnDsaSigningKeyStandard`) may retain key material
/// in memory until overwritten by the operating system or subsequent allocations.
///
/// **Best-effort zeroization approach:**
/// - The `bytes` field containing the serialized secret key is automatically zeroized
///   when this struct is dropped via the `Drop` and `Zeroize` implementations.
/// - The `inner` field from the external `fn-dsa` crate cannot be directly zeroized
///   as it doesn't implement `Zeroize`.
///
/// **For maximum security**, consider using ML-DSA (`arc_primitives::sig::mldsa`)
/// which has full zeroization support for all key material.
pub struct SigningKey {
    /// Security level for this key
    security_level: FNDsaSecurityLevel,
    /// Internal signing key from fn-dsa crate
    /// Note: Cannot be zeroized as FnDsaSigningKeyStandard doesn't implement Zeroize
    inner: FnDsaSigningKeyStandard,
    /// Serialized key bytes for secure storage (zeroized on drop)
    bytes: Vec<u8>,
    /// Associated verifying key (public key)
    pub verifying_key: VerifyingKey,
}

impl Drop for SigningKey {
    fn drop(&mut self) {
        // Zeroize the serialized key bytes in-place (preserving length for testing)
        // This zeros each byte individually rather than using Vec::zeroize which clears
        for byte in &mut self.bytes {
            byte.zeroize();
        }
        // Note: self.inner (FnDsaSigningKeyStandard) cannot be zeroized
        // as it's from an external crate that doesn't implement Zeroize.
        // The bytes field contains the same key material and IS zeroized.
    }
}

impl Zeroize for SigningKey {
    fn zeroize(&mut self) {
        // Zero each byte in-place to preserve the length
        // This allows verification that zeroization occurred
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

impl SigningKey {
    /// Create signing key from bytes
    ///
    /// # Errors
    /// Returns an error if the key length is incorrect or decoding fails.
    pub fn from_bytes(bytes: Vec<u8>, security_level: FNDsaSecurityLevel) -> Result<Self> {
        if bytes.len() != security_level.signing_key_size() {
            return Err(LatticeArcError::InvalidKey(format!(
                "Invalid FN-DSA signing key length: expected {}, got {}",
                security_level.signing_key_size(),
                bytes.len()
            )));
        }
        {
            let inner = FnDsaSigningKeyStandard::decode(&bytes).ok_or_else(|| {
                LatticeArcError::InvalidKey("Failed to decode signing key".to_string())
            })?;

            // Extract verifying key from signing key
            let mut vrfy_key_bytes = vec![0u8; security_level.verifying_key_size()];
            inner.to_verifying_key(&mut vrfy_key_bytes);
            let verifying_key = VerifyingKey::from_bytes(vrfy_key_bytes, security_level)?;

            Ok(Self { security_level, inner, bytes, verifying_key })
        }
    }

    /// Convert signing key to bytes
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    /// Get the verifying key
    #[must_use]
    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }

    /// Get the security level of this signing key
    #[must_use]
    pub fn security_level(&self) -> FNDsaSecurityLevel {
        self.security_level
    }

    /// Sign a message
    ///
    /// # Errors
    /// Returns an error if the fn_dsa feature is not enabled.
    #[instrument(level = "debug", skip(self, rng, message), fields(security_level = ?self.security_level, message_len = message.len()))]
    pub fn sign<R: RngCore + rand::CryptoRng>(
        &mut self,
        rng: &mut R,
        message: &[u8],
    ) -> Result<Signature> {
        {
            let logn = match self.security_level {
                FNDsaSecurityLevel::Level512 => FN_DSA_LOGN_512,
                FNDsaSecurityLevel::Level1024 => FN_DSA_LOGN_1024,
            };
            let mut sig_bytes = vec![0u8; signature_size(logn)];
            self.inner.sign(rng, &DOMAIN_NONE, &HASH_ID_RAW, message, &mut sig_bytes);
            Signature::from_bytes(sig_bytes)
        }
    }
}

/// FN-DSA keypair
///
/// Contains both signing key (secret) and verifying key (public) for FN-DSA.
/// Provides a convenient interface for key generation and signing operations.
///
/// # Usage
///
/// ```ignore
/// use arc_primitives::sig::fndsa::{KeyPair, FNDsaSecurityLevel};
/// use rand::rngs::OsRng;
///
/// let mut rng = OsRng;
/// let mut keypair = KeyPair::generate(&mut rng, FNDsaSecurityLevel::Level512)?;
///
/// // Sign a message
/// let message = b"Important data";
/// let signature = keypair.sign(&mut rng, message)?;
///
/// // Verify the signature
/// let is_valid = keypair.verify(message, &signature)?;
/// assert!(is_valid);
///
/// // Export keys for storage/distribution
/// let sk_bytes = keypair.signing_key().to_bytes();
/// let vk_bytes = keypair.verifying_key().to_bytes();
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
///
/// # Security
///
/// - The signing key component must be kept secret
/// - The verifying key component can be freely distributed
/// - Both keys are encoded according to FIPS 206
/// - Signing key material is zeroized on drop (see [`SigningKey`] for limitations)
#[derive(Debug)]
pub struct KeyPair {
    /// Secret signing key component
    pub signing_key: SigningKey,
    /// Public verifying key component
    pub verifying_key: VerifyingKey,
}

impl Drop for KeyPair {
    fn drop(&mut self) {
        // Zeroize the signing key (delegates to SigningKey's Zeroize impl)
        self.signing_key.zeroize();
    }
}

impl Zeroize for KeyPair {
    fn zeroize(&mut self) {
        self.signing_key.zeroize();
        // verifying_key is public data, no need to zeroize
    }
}

impl KeyPair {
    /// Generates a new FN-DSA keypair for the specified security level
    ///
    /// This function creates both signing and verifying keys using cryptographically
    /// secure random number generation. The key generation follows the
    /// specification in [FIPS 206](https://csrc.nist.gov/pubs/fips/206/final/).
    /// After key generation, a FIPS 140-3 Pairwise Consistency Test (PCT)
    /// is performed to verify the keypair is valid.
    ///
    /// # Arguments
    ///
    /// * `rng` - Cryptographically secure random number generator
    /// * `security_level` - Desired security level (Level512 or Level1024)
    ///
    /// # Returns
    ///
    /// A new [`KeyPair`] containing both signing and verifying keys.
    ///
    /// # Errors
    ///
    /// Returns an error if the `fn_dsa` feature is not enabled, if
    /// key generation fails (e.g., RNG failure), or if the PCT fails.
    ///
    /// # Security
    ///
    /// - Uses only cryptographically secure randomness
    /// - Keys are generated according to FIPS 206 specification
    /// - Secret key data is automatically zeroized when dropped
    /// - PCT ensures keypair consistency before use
    ///
    /// # Example
    ///
    /// ```ignore
    /// use arc_primitives::sig::fndsa::{KeyPair, FNDsaSecurityLevel};
    /// use rand::rngs::OsRng;
    ///
    /// let mut rng = OsRng;
    /// let keypair = KeyPair::generate(&mut rng, FNDsaSecurityLevel::Level512)?;
    ///
    /// println!("Public key: {} bytes", keypair.verifying_key().to_bytes().len());
    /// println!("Secret key: {} bytes", keypair.signing_key().to_bytes().len());
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[instrument(level = "debug", skip(rng), fields(security_level = ?security_level))]
    pub fn generate<R: RngCore + rand::CryptoRng>(
        rng: &mut R,
        security_level: FNDsaSecurityLevel,
    ) -> Result<Self> {
        {
            let mut kg = KeyPairGeneratorStandard::default();
            let logn = security_level.to_logn();

            let mut sk_bytes = vec![0u8; sign_key_size(logn)];
            let mut vk_bytes = vec![0u8; vrfy_key_size(logn)];

            kg.keygen(logn, rng, &mut sk_bytes, &mut vk_bytes);

            let signing_key = SigningKey::from_bytes(sk_bytes, security_level)?;
            let verifying_key = VerifyingKey::from_bytes(vk_bytes, security_level)?;

            let mut keypair = Self { signing_key, verifying_key };

            // FIPS 140-3 Pairwise Consistency Test (PCT)
            // Sign and verify a test message to ensure the keypair is consistent
            crate::pct::pct_fn_dsa_keypair(&mut keypair)
                .map_err(|e| LatticeArcError::KeyGenerationError(format!("PCT failed: {}", e)))?;

            Ok(keypair)
        }
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

    /// Signs a message using the signing key
    ///
    /// Generates a digital signature for the provided message using FN-DSA.
    /// Each signature operation requires fresh randomness from the provided RNG.
    ///
    /// # Arguments
    ///
    /// * `rng` - Cryptographically secure random number generator for nonce generation
    /// * `message` - The message to sign (any length)
    ///
    /// # Returns
    ///
    /// A [`Signature`] that can be verified with the corresponding public key.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `fn_dsa` feature is not enabled
    /// - RNG operation fails
    ///
    /// # Security
    ///
    /// - Each signature uses fresh, unpredictable randomness
    /// - Operations are constant-time to prevent timing attacks
    /// - Signing key is never exposed during operation
    ///
    /// # Example
    ///
    /// ```ignore
    /// use arc_primitives::sig::fndsa::{KeyPair, FNDsaSecurityLevel};
    /// use rand::rngs::OsRng;
    ///
    /// let mut rng = OsRng;
    /// let mut keypair = KeyPair::generate(&mut rng, FNDsaSecurityLevel::Level512)?;
    ///
    /// let message = b"Critical transaction data";
    /// let signature = keypair.sign(&mut rng, message)?;
    ///
    /// // Verify the signature
    /// let is_valid = keypair.verify(message, &signature)?;
    /// assert!(is_valid);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn sign<R: RngCore + rand::CryptoRng>(
        &mut self,
        rng: &mut R,
        message: &[u8],
    ) -> Result<Signature> {
        self.signing_key.sign(rng, message)
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
    /// ```ignore
    /// use arc_primitives::sig::fndsa::{KeyPair, FNDsaSecurityLevel};
    /// use rand::rngs::OsRng;
    ///
    /// let mut rng = OsRng;
    /// let mut keypair = KeyPair::generate(&mut rng, FNDsaSecurityLevel::Level512)?;
    ///
    /// let message = b"Important document";
    /// let signature = keypair.sign(&mut rng, message)?;
    ///
    /// // Verify valid signature
    /// let is_valid = keypair.verify(message, &signature)?;
    /// assert!(is_valid);
    ///
    /// // Reject invalid message
    /// let wrong_message = b"Tampered message";
    /// let is_valid = keypair.verify(wrong_message, &signature)?;
    /// assert!(!is_valid);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<bool> {
        self.verifying_key.verify(message, signature)
    }
}

// Type aliases for convenience

/// FN-DSA signing key using the standard format
pub type FnDsaSigningKeyStandard = fn_dsa::SigningKeyStandard;
/// FN-DSA verifying key using the standard format
pub type FnDsaVerifyingKeyStandard = fn_dsa::VerifyingKeyStandard;
/// FN-DSA keypair generator using the standard format
pub type FnDsaKeyPairGeneratorStandard = KeyPairGeneratorStandard;

#[cfg(test)]
#[allow(clippy::unwrap_used)] // Tests use unwrap for simplicity
#[allow(clippy::expect_used)] // Tests use expect for simplicity
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_fndsa_key_generation_512() {
        std::thread::Builder::new()
            .stack_size(32 * 1024 * 1024)
            .spawn(|| {
                let mut rng = OsRng;
                let keypair = KeyPair::generate(&mut rng, FNDsaSecurityLevel::Level512).unwrap();

                assert_eq!(
                    keypair.signing_key().to_bytes().len(),
                    FNDsaSecurityLevel::Level512.signing_key_size()
                );
                assert_eq!(
                    keypair.verifying_key().to_bytes().len(),
                    FNDsaSecurityLevel::Level512.verifying_key_size()
                );
            })
            .expect("Thread spawn failed")
            .join()
            .expect("Thread join failed");
    }

    #[test]
    fn test_fndsa_key_generation_1024() {
        std::thread::Builder::new()
            .stack_size(32 * 1024 * 1024)
            .spawn(|| {
                let mut rng = OsRng;
                let keypair = KeyPair::generate(&mut rng, FNDsaSecurityLevel::Level1024).unwrap();

                assert_eq!(
                    keypair.signing_key().to_bytes().len(),
                    FNDsaSecurityLevel::Level1024.signing_key_size()
                );
                assert_eq!(
                    keypair.verifying_key().to_bytes().len(),
                    FNDsaSecurityLevel::Level1024.verifying_key_size()
                );
            })
            .expect("Thread spawn failed")
            .join()
            .expect("Thread join failed");
    }

    #[test]
    fn test_fndsa_signature_consistency() {
        std::thread::Builder::new()
            .stack_size(32 * 1024 * 1024)
            .spawn(|| {
                let mut rng = OsRng;
                let mut keypair =
                    KeyPair::generate(&mut rng, FNDsaSecurityLevel::Level512).unwrap();
                let message = b"Hello, FN-DSA world!";

                let signature = keypair.sign(&mut rng, message).unwrap();
                let verified = keypair.verify(message, &signature).unwrap();
                assert!(verified);
            })
            .expect("Thread spawn failed")
            .join()
            .expect("Thread join failed");
    }

    #[test]
    fn test_fndsa_wrong_message() {
        std::thread::Builder::new()
            .stack_size(32 * 1024 * 1024)
            .spawn(|| {
                let mut rng = OsRng;
                let mut keypair =
                    KeyPair::generate(&mut rng, FNDsaSecurityLevel::Level512).unwrap();
                let message = b"Correct message";
                let wrong_message = b"Wrong message";

                let signature = keypair.sign(&mut rng, message).unwrap();
                let verified = keypair.verify(wrong_message, &signature).unwrap();
                assert!(!verified);
            })
            .expect("Thread spawn failed")
            .join()
            .expect("Thread join failed");
    }

    #[test]
    fn test_fndsa_key_serialization() {
        std::thread::Builder::new()
            .stack_size(32 * 1024 * 1024)
            .spawn(|| {
                let mut rng = OsRng;
                let keypair = KeyPair::generate(&mut rng, FNDsaSecurityLevel::Level512).unwrap();

                // Serialize/deserialize signing key
                let sk_bytes = keypair.signing_key().to_bytes();
                let deserialized_sk =
                    SigningKey::from_bytes(sk_bytes, FNDsaSecurityLevel::Level512).unwrap();
                assert_eq!(keypair.signing_key().to_bytes(), deserialized_sk.to_bytes());

                // Serialize/deserialize verifying key
                let vk_bytes = keypair.verifying_key().to_bytes();
                let deserialized_vk =
                    VerifyingKey::from_bytes(vk_bytes, FNDsaSecurityLevel::Level512).unwrap();
                assert_eq!(keypair.verifying_key().to_bytes(), deserialized_vk.to_bytes());
            })
            .expect("Thread spawn failed")
            .join()
            .expect("Thread join failed");
    }

    #[test]
    fn test_signature_serialization() {
        std::thread::Builder::new()
            .stack_size(32 * 1024 * 1024)
            .spawn(|| {
                let mut rng = OsRng;
                let mut keypair =
                    KeyPair::generate(&mut rng, FNDsaSecurityLevel::Level512).unwrap();
                let message = b"Test message";
                let signature = keypair.sign(&mut rng, message).unwrap();

                let sig_bytes = signature.to_bytes();
                let deserialized_sig = Signature::from_bytes(sig_bytes).unwrap();
                assert_eq!(signature.to_bytes(), deserialized_sig.to_bytes());
            })
            .expect("Thread spawn failed")
            .join()
            .expect("Thread join failed");
    }

    #[test]
    fn test_security_level_sizes() {
        let level512 = FNDsaSecurityLevel::Level512;
        let level1024 = FNDsaSecurityLevel::Level1024;

        assert_eq!(level512.signature_size(), 666);
        assert_eq!(level512.signing_key_size(), 1281);
        assert_eq!(level512.verifying_key_size(), 897);

        assert_eq!(level1024.signature_size(), 1280);
        assert_eq!(level1024.signing_key_size(), 2305);
        assert_eq!(level1024.verifying_key_size(), 1793);
    }

    #[test]
    fn test_empty_signature() {
        let result = Signature::from_bytes(vec![]);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_key_length() {
        let result = VerifyingKey::from_bytes(vec![0u8; 100], FNDsaSecurityLevel::Level512);
        assert!(result.is_err());

        let result = SigningKey::from_bytes(vec![0u8; 100], FNDsaSecurityLevel::Level512);
        assert!(result.is_err());
    }

    #[test]
    fn test_security_level_default() {
        let level = FNDsaSecurityLevel::default();
        assert_eq!(level, FNDsaSecurityLevel::Level512);
    }

    #[test]
    fn test_security_level_to_logn() {
        assert_eq!(FNDsaSecurityLevel::Level512.to_logn(), FN_DSA_LOGN_512);
        assert_eq!(FNDsaSecurityLevel::Level1024.to_logn(), FN_DSA_LOGN_1024);
    }

    /// Test that verifies the key_bytes field is properly zeroized when the signing key
    /// is dropped or explicitly zeroized.
    ///
    /// # Security Note
    ///
    /// This test verifies our best-effort zeroization approach for FN-DSA keys.
    /// The `bytes` field containing the serialized key material is zeroized,
    /// but the `inner` field from the external `fn-dsa` crate cannot be zeroized
    /// as it doesn't implement the `Zeroize` trait.
    #[test]
    fn test_signing_key_zeroization() {
        std::thread::Builder::new()
            .stack_size(32 * 1024 * 1024)
            .spawn(|| {
                let mut rng = OsRng;

                // Create a signing key directly from bytes to avoid KeyPair's Drop constraint
                let keypair = KeyPair::generate(&mut rng, FNDsaSecurityLevel::Level512).unwrap();
                let sk_bytes = keypair.signing_key().to_bytes();
                drop(keypair);

                // Create a new signing key from the bytes
                let mut signing_key =
                    SigningKey::from_bytes(sk_bytes, FNDsaSecurityLevel::Level512).unwrap();

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
    fn test_keypair_zeroization() {
        std::thread::Builder::new()
            .stack_size(32 * 1024 * 1024)
            .spawn(|| {
                let mut rng = OsRng;
                let mut keypair =
                    KeyPair::generate(&mut rng, FNDsaSecurityLevel::Level512).unwrap();

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
}

#[cfg(test)]
#[allow(clippy::unwrap_used)] // Tests use unwrap for simplicity
#[allow(clippy::expect_used)] // Tests use expect for simplicity
mod integration_tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_multiple_messages_same_key() {
        std::thread::Builder::new()
            .stack_size(32 * 1024 * 1024)
            .spawn(|| {
                let mut rng = OsRng;
                let mut keypair =
                    KeyPair::generate(&mut rng, FNDsaSecurityLevel::Level512).unwrap();

                let message1 = b"Message 1";
                let message2 = b"Message 2";

                let sig1 = keypair.sign(&mut rng, message1).unwrap();
                let sig2 = keypair.sign(&mut rng, message2).unwrap();

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
    fn test_level1024_signature() {
        std::thread::Builder::new()
            .stack_size(32 * 1024 * 1024)
            .spawn(|| {
                let mut rng = OsRng;
                let mut keypair =
                    KeyPair::generate(&mut rng, FNDsaSecurityLevel::Level1024).unwrap();
                let message = b"Test message for FN-DSA-1024";

                let signature = keypair.sign(&mut rng, message).unwrap();
                assert_eq!(signature.len(), 1280);

                let verified = keypair.verify(message, &signature).unwrap();
                assert!(verified);
            })
            .expect("Thread spawn failed")
            .join()
            .expect("Thread join failed");
    }
}
