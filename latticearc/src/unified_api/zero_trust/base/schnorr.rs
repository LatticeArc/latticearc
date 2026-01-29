#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

//! Schnorr proof implementation using secp256k1

use k256::{
    elliptic_curve::{
        generic_array::GenericArray,
        sec1::{FromEncodedPoint, ToEncodedPoint},
        PrimeField,
    },
    ProjectivePoint, Scalar,
};
use sha2::{Digest, Sha256};

use crate::unified_api::error::CryptoError;

/// Schnorr proof structure using secp256k1
#[derive(Debug, Clone)]
pub struct SchnorrProof {
    /// Commitment point R = g^r (as compressed bytes, 33 bytes)
    pub commitment: Vec<u8>,
    /// Response scalar s = r + e * x (32 bytes)
    pub response: Vec<u8>,
}

impl SchnorrProof {
    /// Serialize the Schnorr proof to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(65);
        bytes.extend_from_slice(&self.commitment);
        bytes.extend_from_slice(&self.response);
        bytes
    }

    /// Deserialize Schnorr proof from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() < 65 {
            return Err(CryptoError::InvalidInput("Invalid Schnorr proof length".to_string()));
        }

        Ok(Self {
            commitment: bytes[..33].to_vec(),
            response: bytes[33..65].to_vec(),
        })
    }

    /// Validate the proof structure
    pub fn is_valid(&self) -> bool {
        self.commitment.len() == 33 && self.response.len() == 32
    }
}

/// Parse public key bytes to ProjectivePoint
pub fn parse_public_key_point(public_key: &[u8]) -> Result<ProjectivePoint, CryptoError> {
    let encoded_point = k256::EncodedPoint::from_bytes(public_key)
        .map_err(|e| CryptoError::InvalidInput(format!("Invalid public key encoding: {}", e)))?;

    ProjectivePoint::from_encoded_point(&encoded_point)
        .into_option()
        .ok_or_else(|| CryptoError::InvalidInput("Invalid public key point".to_string()))
}

/// Parse scalar bytes to Scalar
pub fn parse_scalar(bytes: &[u8]) -> Result<Scalar, CryptoError> {
    let bytes_array = GenericArray::clone_from_slice(bytes);
    let scalar = Scalar::from_repr(bytes_array)
        .into_option()
        .ok_or_else(|| CryptoError::InvalidInput("Invalid scalar value".to_string()))?;

    Ok(scalar)
}

/// Compute Schnorr challenge: e = H(g || pub_key || R || challenge)
pub fn compute_schnorr_challenge(
    public_key: &ProjectivePoint,
    commitment: &ProjectivePoint,
    challenge: &[u8],
) -> Result<Scalar, CryptoError> {
    let mut hasher = Sha256::new();

    // Hash generator point g (compressed)
    hasher.update(ProjectivePoint::GENERATOR.to_encoded_point(true).as_bytes());

    // Hash public key (compressed)
    hasher.update(public_key.to_encoded_point(true).as_bytes());

    // Hash commitment R (compressed)
    hasher.update(commitment.to_encoded_point(true).as_bytes());

    // Hash challenge
    hasher.update(challenge);

    let hash = hasher.finalize();
    let hash_array = GenericArray::clone_from_slice(&hash);
    let scalar = Scalar::from_repr(hash_array)
        .into_option()
        .ok_or_else(|| CryptoError::InvalidInput("Hash to scalar failed".to_string()))?;

    Ok(scalar)
}

/// Convert scalar to bytes (32 bytes, big-endian)
pub fn scalar_to_bytes(scalar: &Scalar) -> [u8; 32] {
    scalar.to_bytes().into()
}
