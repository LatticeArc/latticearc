#![deny(unsafe_code)]
#![warn(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

//! # ML-DSA (FIPS 204) Digital Signatures
//!
//! ## FIPS 140-3 Certification Notice
//!
//! **Current Implementation**: Uses the `fips204` crate (pure Rust, NOT independently audited)
//!
//! **For FIPS 140-3 certification**, this module will need to migrate to `aws-lc-rs` when
//! the ML-DSA Rust API becomes available. Track progress at:
//! - <https://github.com/aws/aws-lc-rs/issues/773>
//!
//! **Migration Status**: Awaiting aws-lc-rs ML-DSA API exposure
//! **Expected Timeline**: TBD (check issue for updates)
//!
//! See `docs/ML_DSA_MIGRATION.md` for the complete migration plan.
//!
//! ## Usage for Non-FIPS Applications
//!
//! The current implementation is functionally correct and suitable for:
//! - Development and testing
//! - Non-regulated applications
//! - Applications not requiring FIPS 140-3 certification
//!
//! ## FIPS 204 Standard
//!
//! FIPS 204 specifies the Module-Lattice-Based Digital Signature Algorithm (ML-DSA),
//! which provides post-quantum security for digital signatures.
//!
//! ## Security Level
//!
//! ML-DSA provides EUF-CMA (Existential Unforgeability under Chosen Message Attacks)
//! security and is believed to be secure against quantum adversaries.
//!
//! ## Parameter Sets
//!
//! | Parameter Set | Public Key | Signature | NIST Level |
//! |---------------|------------|-----------|------------|
//! | ML-DSA-44     | ~1.3 KB    | ~2.4 KB   | 2          |
//! | ML-DSA-65     | ~2.0 KB    | ~3.3 KB   | 3          |
//! | ML-DSA-87     | ~2.6 KB    | ~4.6 KB   | 5          |
//!
//! ## Backend Selection (Future)
//!
//! When aws-lc-rs ML-DSA support is available, the backend will be selectable via
//! feature flags:
//!
//! ```toml
//! # Future configuration (not yet available)
//! [dependencies]
//! arc-primitives = { version = "0.1", features = ["ml-dsa-aws-lc"] }
//! ```

use fips204::{
    ml_dsa_44, ml_dsa_65, ml_dsa_87,
    traits::{SerDes, Signer, Verifier},
};
use subtle::{Choice, ConstantTimeEq};
use thiserror::Error;
use tracing::instrument;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// ML-DSA parameter sets for different security levels
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum MlDsaParameterSet {
    /// ML-DSA-44: NIST Level 2 security (~128-bit classical security)
    MLDSA44,
    /// ML-DSA-65: NIST Level 3 security (~192-bit classical security)
    MLDSA65,
    /// ML-DSA-87: NIST Level 5 security (~256-bit classical security)
    MLDSA87,
}

impl MlDsaParameterSet {
    /// Returns the name of the parameter set
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::MLDSA44 => "ML-DSA-44",
            Self::MLDSA65 => "ML-DSA-65",
            Self::MLDSA87 => "ML-DSA-87",
        }
    }

    /// Returns the public key size in bytes
    #[must_use]
    pub const fn public_key_size(&self) -> usize {
        match self {
            Self::MLDSA44 => 1312,
            Self::MLDSA65 => 1952,
            Self::MLDSA87 => 2592,
        }
    }

    /// Returns the secret key size in bytes
    #[must_use]
    pub const fn secret_key_size(&self) -> usize {
        match self {
            Self::MLDSA44 => 2560,
            Self::MLDSA65 => 4032,
            Self::MLDSA87 => 4896,
        }
    }

    /// Returns the signature size in bytes
    #[must_use]
    pub const fn signature_size(&self) -> usize {
        match self {
            Self::MLDSA44 => 2420,
            Self::MLDSA65 => 3309,
            Self::MLDSA87 => 4627,
        }
    }

    /// Returns the NIST security level
    #[must_use]
    pub const fn nist_security_level(&self) -> u8 {
        match self {
            Self::MLDSA44 => 2,
            Self::MLDSA65 => 3,
            Self::MLDSA87 => 5,
        }
    }
}

/// Error types for ML-DSA operations
#[derive(Debug, Error)]
pub enum MlDsaError {
    /// Key generation failed
    #[error("Key generation failed: {0}")]
    KeyGenerationError(String),

    /// Signing failed
    #[error("Signing failed: {0}")]
    SigningError(String),

    /// Verification failed
    #[error("Verification failed: {0}")]
    VerificationError(String),

    /// Invalid key length
    #[error("Invalid key length: expected {expected}, got {actual}")]
    InvalidKeyLength {
        /// Expected key size
        expected: usize,
        /// Actual key size
        actual: usize,
    },

    /// Invalid signature length
    #[error("Invalid signature length: expected {expected}, got {actual}")]
    InvalidSignatureLength {
        /// Expected signature size
        expected: usize,
        /// Actual signature size
        actual: usize,
    },

    /// Invalid parameter set
    #[error("Invalid parameter set: {0}")]
    InvalidParameterSet(String),

    /// ML-DSA feature not enabled
    #[error("ML-DSA feature not enabled")]
    FeatureNotEnabled,

    /// Cryptographic operation failed
    #[error("Cryptographic operation failed: {0}")]
    CryptoError(String),
}

/// ML-DSA public key (FIPS 204 format)
#[derive(Debug, Clone)]
pub struct MlDsaPublicKey {
    /// The parameter set for this key
    pub parameter_set: MlDsaParameterSet,
    /// Serialized public key bytes
    pub data: Vec<u8>,
}

impl MlDsaPublicKey {
    /// Creates a new ML-DSA public key from raw bytes
    ///
    /// # Errors
    /// Returns an error if the key length does not match the expected size for the parameter set.
    pub fn new(parameter_set: MlDsaParameterSet, data: Vec<u8>) -> Result<Self, MlDsaError> {
        let expected_size = parameter_set.public_key_size();
        if data.len() != expected_size {
            return Err(MlDsaError::InvalidKeyLength {
                expected: expected_size,
                actual: data.len(),
            });
        }
        Ok(Self { parameter_set, data })
    }

    /// Returns the size of the public key in bytes
    #[must_use]
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Returns true if the public key is empty
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Serializes the public key to bytes
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }
}

/// ML-DSA secret key (FIPS 204 format)
///
/// # Security
///
/// - Fields are private to prevent direct access to secret material
/// - Implements `ZeroizeOnDrop` for automatic memory cleanup
/// - Implements `ConstantTimeEq` for timing-safe comparisons
/// - Does not implement `Clone` to prevent unzeroized copies
#[derive(Debug, Zeroize, ZeroizeOnDrop)]
pub struct MlDsaSecretKey {
    /// The parameter set for this key
    #[zeroize(skip)]
    parameter_set: MlDsaParameterSet,
    /// Serialized secret key bytes (zeroized on drop)
    data: Vec<u8>,
}

impl MlDsaSecretKey {
    /// Creates a new ML-DSA secret key from raw bytes
    ///
    /// # Errors
    /// Returns an error if the key length does not match the expected size for the parameter set.
    pub fn new(parameter_set: MlDsaParameterSet, data: Vec<u8>) -> Result<Self, MlDsaError> {
        let expected_size = parameter_set.secret_key_size();
        if data.len() != expected_size {
            return Err(MlDsaError::InvalidKeyLength {
                expected: expected_size,
                actual: data.len(),
            });
        }
        Ok(Self { parameter_set, data })
    }

    /// Returns the parameter set for this key
    #[must_use]
    pub fn parameter_set(&self) -> MlDsaParameterSet {
        self.parameter_set
    }

    /// Returns the size of the secret key in bytes
    #[must_use]
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Returns true if the secret key is empty
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Returns a reference to the secret key bytes
    ///
    /// # Security Warning
    /// Handle the returned bytes with care. Do not copy or store them
    /// without proper zeroization.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }
}

impl ConstantTimeEq for MlDsaSecretKey {
    fn ct_eq(&self, other: &Self) -> Choice {
        // Compare parameter set discriminant in constant time
        let param_eq = (self.parameter_set as u8).ct_eq(&(other.parameter_set as u8));
        // Compare data in constant time
        let data_eq = self.data.ct_eq(&other.data);
        param_eq & data_eq
    }
}

impl PartialEq for MlDsaSecretKey {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Eq for MlDsaSecretKey {}

/// ML-DSA signature (FIPS 204 format)
#[derive(Debug, Clone)]
pub struct MlDsaSignature {
    /// The parameter set used to create this signature
    pub parameter_set: MlDsaParameterSet,
    /// Serialized signature bytes
    pub data: Vec<u8>,
}

impl MlDsaSignature {
    /// Creates a new ML-DSA signature from raw bytes
    ///
    /// # Errors
    /// Returns an error if the signature length does not match the expected size for the parameter set.
    pub fn new(parameter_set: MlDsaParameterSet, data: Vec<u8>) -> Result<Self, MlDsaError> {
        let expected_size = parameter_set.signature_size();
        if data.len() != expected_size {
            return Err(MlDsaError::InvalidSignatureLength {
                expected: expected_size,
                actual: data.len(),
            });
        }
        Ok(Self { parameter_set, data })
    }

    /// Returns the size of the signature in bytes
    #[must_use]
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Returns true if the signature is empty
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Serializes the signature to bytes
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }
}

/// Generate an ML-DSA keypair for the specified parameter set
///
/// This function generates a new ML-DSA keypair and performs a FIPS 140-3
/// Pairwise Consistency Test (PCT) to verify the keypair is valid before
/// returning it.
///
/// # Errors
/// Returns an error if key generation fails, the ml_dsa feature is not enabled,
/// or the PCT fails (indicating a corrupted keypair).
#[instrument(level = "debug", fields(parameter_set = ?parameter_set))]
pub fn generate_keypair(
    parameter_set: MlDsaParameterSet,
) -> Result<(MlDsaPublicKey, MlDsaSecretKey), MlDsaError> {
    let (pk, sk) = match parameter_set {
        MlDsaParameterSet::MLDSA44 => {
            let (pk, sk) = ml_dsa_44::try_keygen().map_err(|e| {
                MlDsaError::KeyGenerationError(format!("ML-DSA-44 key generation failed: {}", e))
            })?;
            (
                MlDsaPublicKey { parameter_set, data: pk.into_bytes().to_vec() },
                MlDsaSecretKey { parameter_set, data: sk.into_bytes().to_vec() },
            )
        }
        MlDsaParameterSet::MLDSA65 => {
            let (pk, sk) = ml_dsa_65::try_keygen().map_err(|e| {
                MlDsaError::KeyGenerationError(format!("ML-DSA-65 key generation failed: {}", e))
            })?;
            (
                MlDsaPublicKey { parameter_set, data: pk.into_bytes().to_vec() },
                MlDsaSecretKey { parameter_set, data: sk.into_bytes().to_vec() },
            )
        }
        MlDsaParameterSet::MLDSA87 => {
            let (pk, sk) = ml_dsa_87::try_keygen().map_err(|e| {
                MlDsaError::KeyGenerationError(format!("ML-DSA-87 key generation failed: {}", e))
            })?;
            (
                MlDsaPublicKey { parameter_set, data: pk.into_bytes().to_vec() },
                MlDsaSecretKey { parameter_set, data: sk.into_bytes().to_vec() },
            )
        }
    };

    // FIPS 140-3 Pairwise Consistency Test (PCT)
    // Sign and verify a test message to ensure the keypair is consistent
    crate::pct::pct_ml_dsa(&pk, &sk)
        .map_err(|e| MlDsaError::KeyGenerationError(format!("PCT failed: {}", e)))?;

    Ok((pk, sk))
}

/// Sign a message using ML-DSA
///
/// # Errors
/// Returns an error if signing fails, the key is invalid, or the ml_dsa feature is not enabled.
#[instrument(level = "debug", skip(secret_key, message, context), fields(parameter_set = ?secret_key.parameter_set, message_len = message.len(), context_len = context.len()))]
pub fn sign(
    secret_key: &MlDsaSecretKey,
    message: &[u8],
    context: &[u8],
) -> Result<MlDsaSignature, MlDsaError> {
    let parameter_set = secret_key.parameter_set();

    let signature = match parameter_set {
        MlDsaParameterSet::MLDSA44 => {
            let sk_bytes: [u8; 2560] = secret_key.as_bytes().try_into().map_err(|_e| {
                MlDsaError::InvalidKeyLength { expected: 2560, actual: secret_key.len() }
            })?;
            let sk = ml_dsa_44::PrivateKey::try_from_bytes(sk_bytes).map_err(|e| {
                MlDsaError::SigningError(format!(
                    "Failed to deserialize ML-DSA-44 secret key: {}",
                    e
                ))
            })?;
            let sig = sk.try_sign(message, context).map_err(|e| {
                MlDsaError::SigningError(format!("ML-DSA-44 signing failed: {}", e))
            })?;
            MlDsaSignature { parameter_set, data: sig.to_vec() }
        }
        MlDsaParameterSet::MLDSA65 => {
            let sk_bytes: [u8; 4032] = secret_key.as_bytes().try_into().map_err(|_e| {
                MlDsaError::InvalidKeyLength { expected: 4032, actual: secret_key.len() }
            })?;
            let sk = ml_dsa_65::PrivateKey::try_from_bytes(sk_bytes).map_err(|e| {
                MlDsaError::SigningError(format!(
                    "Failed to deserialize ML-DSA-65 secret key: {}",
                    e
                ))
            })?;
            let sig = sk.try_sign(message, context).map_err(|e| {
                MlDsaError::SigningError(format!("ML-DSA-65 signing failed: {}", e))
            })?;
            MlDsaSignature { parameter_set, data: sig.to_vec() }
        }
        MlDsaParameterSet::MLDSA87 => {
            let sk_bytes: [u8; 4896] = secret_key.as_bytes().try_into().map_err(|_e| {
                MlDsaError::InvalidKeyLength { expected: 4896, actual: secret_key.len() }
            })?;
            let sk = ml_dsa_87::PrivateKey::try_from_bytes(sk_bytes).map_err(|e| {
                MlDsaError::SigningError(format!(
                    "Failed to deserialize ML-DSA-87 secret key: {}",
                    e
                ))
            })?;
            let sig = sk.try_sign(message, context).map_err(|e| {
                MlDsaError::SigningError(format!("ML-DSA-87 signing failed: {}", e))
            })?;
            MlDsaSignature { parameter_set, data: sig.to_vec() }
        }
    };

    Ok(signature)
}

/// Verify a signature using ML-DSA
///
/// # Errors
/// Returns an error if verification fails due to invalid key or signature format.
#[instrument(level = "debug", skip(public_key, message, signature, context), fields(parameter_set = ?public_key.parameter_set, message_len = message.len(), signature_len = signature.data.len()))]
pub fn verify(
    public_key: &MlDsaPublicKey,
    message: &[u8],
    signature: &MlDsaSignature,
    context: &[u8],
) -> Result<bool, MlDsaError> {
    if public_key.parameter_set != signature.parameter_set {
        return Ok(false);
    }

    let is_valid = match public_key.parameter_set {
        MlDsaParameterSet::MLDSA44 => {
            let pk_bytes: [u8; 1312] = public_key.data.as_slice().try_into().map_err(|_e| {
                MlDsaError::InvalidKeyLength { expected: 1312, actual: public_key.data.len() }
            })?;
            let pk = ml_dsa_44::PublicKey::try_from_bytes(pk_bytes).map_err(|e| {
                MlDsaError::VerificationError(format!(
                    "Failed to deserialize ML-DSA-44 public key: {}",
                    e
                ))
            })?;
            let sig_bytes: [u8; 2420] = signature.data.as_slice().try_into().map_err(|_e| {
                MlDsaError::InvalidSignatureLength { expected: 2420, actual: signature.data.len() }
            })?;
            pk.verify(message, &sig_bytes, context)
        }
        MlDsaParameterSet::MLDSA65 => {
            let pk_bytes: [u8; 1952] = public_key.data.as_slice().try_into().map_err(|_e| {
                MlDsaError::InvalidKeyLength { expected: 1952, actual: public_key.data.len() }
            })?;
            let pk = ml_dsa_65::PublicKey::try_from_bytes(pk_bytes).map_err(|e| {
                MlDsaError::VerificationError(format!(
                    "Failed to deserialize ML-DSA-65 public key: {}",
                    e
                ))
            })?;
            let sig_bytes: [u8; 3309] = signature.data.as_slice().try_into().map_err(|_e| {
                MlDsaError::InvalidSignatureLength { expected: 3309, actual: signature.data.len() }
            })?;
            pk.verify(message, &sig_bytes, context)
        }
        MlDsaParameterSet::MLDSA87 => {
            let pk_bytes: [u8; 2592] = public_key.data.as_slice().try_into().map_err(|_e| {
                MlDsaError::InvalidKeyLength { expected: 2592, actual: public_key.data.len() }
            })?;
            let pk = ml_dsa_87::PublicKey::try_from_bytes(pk_bytes).map_err(|e| {
                MlDsaError::VerificationError(format!(
                    "Failed to deserialize ML-DSA-87 public key: {}",
                    e
                ))
            })?;
            let sig_bytes: [u8; 4627] = signature.data.as_slice().try_into().map_err(|_e| {
                MlDsaError::InvalidSignatureLength { expected: 4627, actual: signature.data.len() }
            })?;
            pk.verify(message, &sig_bytes, context)
        }
    };

    Ok(is_valid)
}

#[cfg(test)]
#[allow(clippy::panic_in_result_fn)] // Tests use assertions for verification
#[allow(clippy::expect_used)] // Tests use expect for simplicity
mod tests {
    use super::*;
    use rand::RngCore;

    fn test_parameter_set(param: MlDsaParameterSet) -> Result<(), MlDsaError> {
        let (pk, sk) = generate_keypair(param)?;

        assert_eq!(pk.parameter_set, param);
        assert_eq!(sk.parameter_set(), param);
        assert_eq!(pk.len(), param.public_key_size());
        assert!(!pk.is_empty());
        assert!(!sk.is_empty());

        let message = b"Test message for ML-DSA";
        let context: &[u8] = &[];

        let signature = sign(&sk, message, context)?;
        assert_eq!(signature.parameter_set, param);
        assert!(!signature.is_empty());

        let is_valid = verify(&pk, message, &signature, context)?;
        assert!(is_valid, "Signature should be valid");

        let wrong_message = b"Wrong message";
        let is_valid = verify(&pk, wrong_message, &signature, context)?;
        assert!(!is_valid, "Signature should be invalid for wrong message");

        let (pk2, _sk2) = generate_keypair(param)?;
        let is_valid = verify(&pk2, message, &signature, context)?;
        assert!(!is_valid, "Signature should be invalid for wrong public key");

        Ok(())
    }

    #[test]
    fn test_ml_dsa_44_key_generation() -> Result<(), MlDsaError> {
        test_parameter_set(MlDsaParameterSet::MLDSA44)
    }

    #[test]
    fn test_ml_dsa_65_key_generation() -> Result<(), MlDsaError> {
        test_parameter_set(MlDsaParameterSet::MLDSA65)
    }

    #[test]
    fn test_ml_dsa_87_key_generation() -> Result<(), MlDsaError> {
        test_parameter_set(MlDsaParameterSet::MLDSA87)
    }

    #[test]
    fn test_ml_dsa_secret_key_zeroization() {
        let (_pk, mut sk) =
            generate_keypair(MlDsaParameterSet::MLDSA44).expect("Key generation should succeed");

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
    fn test_ml_dsa_parameter_set_properties() {
        assert_eq!(MlDsaParameterSet::MLDSA44.name(), "ML-DSA-44");
        assert_eq!(MlDsaParameterSet::MLDSA44.public_key_size(), 1312);
        assert_eq!(MlDsaParameterSet::MLDSA44.secret_key_size(), 2560);
        assert_eq!(MlDsaParameterSet::MLDSA44.signature_size(), 2420);
        assert_eq!(MlDsaParameterSet::MLDSA44.nist_security_level(), 2);

        assert_eq!(MlDsaParameterSet::MLDSA65.name(), "ML-DSA-65");
        assert_eq!(MlDsaParameterSet::MLDSA65.public_key_size(), 1952);
        assert_eq!(MlDsaParameterSet::MLDSA65.secret_key_size(), 4032);
        assert_eq!(MlDsaParameterSet::MLDSA65.signature_size(), 3309);
        assert_eq!(MlDsaParameterSet::MLDSA65.nist_security_level(), 3);

        assert_eq!(MlDsaParameterSet::MLDSA87.name(), "ML-DSA-87");
        assert_eq!(MlDsaParameterSet::MLDSA87.public_key_size(), 2592);
        assert_eq!(MlDsaParameterSet::MLDSA87.secret_key_size(), 4896);
        assert_eq!(MlDsaParameterSet::MLDSA87.signature_size(), 4627);
        assert_eq!(MlDsaParameterSet::MLDSA87.nist_security_level(), 5);
    }

    #[test]
    fn test_ml_dsa_empty_message() {
        let (pk, sk) =
            generate_keypair(MlDsaParameterSet::MLDSA44).expect("Key generation should succeed");
        let message = b"";

        let signature = sign(&sk, message, &[]).expect("Signing should succeed");
        let is_valid = verify(&pk, message, &signature, &[]).expect("Verification should succeed");

        assert!(is_valid, "Empty message should sign and verify correctly");
    }

    #[test]
    fn test_ml_dsa_large_message() {
        let (pk, sk) =
            generate_keypair(MlDsaParameterSet::MLDSA44).expect("Key generation should succeed");
        let mut rng = rand::thread_rng();
        let mut message = vec![0u8; 10_000];
        rng.fill_bytes(&mut message);

        let signature = sign(&sk, &message, &[]).expect("Signing should succeed");
        let is_valid = verify(&pk, &message, &signature, &[]).expect("Verification should succeed");

        assert!(is_valid, "Large message should sign and verify correctly");
    }
}
