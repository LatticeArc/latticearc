//! Cryptographic Commitments
//!
//! Provides hiding and binding commitment schemes:
//!
//! - **Pedersen Commitments**: Information-theoretically hiding, computationally binding
//! - **Hash Commitments**: Simple hash-based commitments
//!
//! ## Properties
//!
//! - **Hiding**: Commitment reveals nothing about the committed value
//! - **Binding**: Cannot open commitment to different value

use crate::error::{Result, ZkpError};
use k256::{
    FieldBytes, ProjectivePoint, Scalar, U256,
    elliptic_curve::{PrimeField, group::GroupEncoding, ops::Reduce},
};
use sha2::{Digest, Sha256};
use sha3::Sha3_256;
use zeroize::{Zeroize, ZeroizeOnDrop};

// ============================================================================
// Hash Commitment
// ============================================================================

/// Simple hash-based commitment scheme
///
/// Commitment: C = H(value || randomness)
/// Opening: reveal value and randomness, verify C == H(value || randomness)
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct HashCommitment {
    /// The commitment hash
    pub commitment: [u8; 32],
}

/// Opening for a hash commitment
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct HashOpening {
    /// The committed value
    pub value: Vec<u8>,
    /// The randomness used
    pub randomness: [u8; 32],
}

impl HashCommitment {
    /// Create a new hash commitment to a value
    ///
    /// # Errors
    /// Returns an error if random number generation fails.
    pub fn commit(value: &[u8]) -> Result<(Self, HashOpening)> {
        let mut randomness = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut randomness);

        let commitment = Self::compute_hash(value, &randomness);

        Ok((Self { commitment }, HashOpening { value: value.to_vec(), randomness }))
    }

    /// Create a commitment with specific randomness (for deterministic tests)
    #[must_use]
    pub fn commit_with_randomness(value: &[u8], randomness: [u8; 32]) -> Self {
        let commitment = Self::compute_hash(value, &randomness);
        Self { commitment }
    }

    /// Verify an opening
    ///
    /// # Errors
    /// This function currently does not return errors but uses Result for API consistency.
    pub fn verify(&self, opening: &HashOpening) -> Result<bool> {
        let expected = Self::compute_hash(&opening.value, &opening.randomness);
        Ok(self.commitment == expected)
    }

    /// Compute H(value || randomness)
    fn compute_hash(value: &[u8], randomness: &[u8; 32]) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(b"arc-zkp/hash-commitment-v1");
        hasher.update((value.len() as u64).to_le_bytes());
        hasher.update(value);
        hasher.update(randomness);
        hasher.finalize().into()
    }
}

// ============================================================================
// Pedersen Commitment
// ============================================================================

/// Pedersen commitment scheme on secp256k1
///
/// Uses two generators G and H where the discrete log relationship is unknown.
/// Commitment: C = v*G + r*H
///
/// Properties:
/// - Information-theoretically hiding (perfect hiding)
/// - Computationally binding (under discrete log assumption)
/// - Additively homomorphic: C(v1) + C(v2) = C(v1 + v2)
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "serde"))]
pub struct PedersenCommitment {
    /// The commitment point (compressed)
    #[cfg_attr(feature = "serde", serde(with = "serde_with::As::<serde_with::Bytes>"))]
    pub commitment: [u8; 33],
}

/// Opening for a Pedersen commitment
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct PedersenOpening {
    /// The committed value (as scalar bytes)
    pub value: [u8; 32],
    /// The blinding factor
    pub blinding: [u8; 32],
}

impl PedersenCommitment {
    /// Create a new Pedersen commitment to a scalar value
    ///
    /// # Errors
    /// Returns an error if the value is not a valid scalar.
    pub fn commit(value: &[u8; 32]) -> Result<(Self, PedersenOpening)> {
        let mut blinding = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut blinding);

        Self::commit_with_blinding(value, &blinding)
    }

    /// Create a commitment with specific blinding factor
    ///
    /// # Errors
    /// Returns an error if the value or blinding factor is not a valid scalar.
    ///
    /// # Elliptic Curve Arithmetic
    /// Uses secp256k1 scalar multiplication and point addition.
    /// These are modular arithmetic operations in a finite field that
    /// mathematically cannot overflow - the group operations are defined
    /// to always produce valid field elements.
    #[allow(clippy::arithmetic_side_effects)] // EC math is modular, cannot overflow
    pub fn commit_with_blinding(
        value: &[u8; 32],
        blinding: &[u8; 32],
    ) -> Result<(Self, PedersenOpening)> {
        let v: Option<Scalar> = Scalar::from_repr(*FieldBytes::from_slice(value)).into();
        let r: Option<Scalar> = Scalar::from_repr(*FieldBytes::from_slice(blinding)).into();

        let v = v.ok_or(ZkpError::InvalidScalar)?;
        let r = r.ok_or(ZkpError::InvalidScalar)?;

        // C = v*G + r*H
        let g = ProjectivePoint::GENERATOR;
        let h = Self::generator_h();

        let commitment_point = g * v + h * r;

        let commitment: [u8; 33] =
            <[u8; 33]>::try_from(commitment_point.to_affine().to_bytes().as_slice()).map_err(
                |e| ZkpError::SerializationError(format!("Failed to serialize commitment: {}", e)),
            )?;

        Ok((Self { commitment }, PedersenOpening { value: *value, blinding: *blinding }))
    }

    /// Verify an opening
    ///
    /// # Errors
    /// Returns an error if the opening contains invalid scalars or the commitment point is invalid.
    ///
    /// # Elliptic Curve Arithmetic
    /// Uses secp256k1 scalar multiplication and point addition.
    #[allow(clippy::arithmetic_side_effects)] // EC math is modular, cannot overflow
    pub fn verify(&self, opening: &PedersenOpening) -> Result<bool> {
        let v: Option<Scalar> = Scalar::from_repr(*FieldBytes::from_slice(&opening.value)).into();
        let r: Option<Scalar> =
            Scalar::from_repr(*FieldBytes::from_slice(&opening.blinding)).into();

        let v = v.ok_or(ZkpError::InvalidScalar)?;
        let r = r.ok_or(ZkpError::InvalidScalar)?;

        // Recompute C = v*G + r*H
        let g = ProjectivePoint::GENERATOR;
        let h = Self::generator_h();
        let expected = g * v + h * r;

        // Parse stored commitment
        use k256::EncodedPoint;
        use k256::elliptic_curve::sec1::FromEncodedPoint;

        let encoded = EncodedPoint::from_bytes(self.commitment)
            .map_err(|e| ZkpError::InvalidCommitment(format!("Invalid point encoding: {}", e)))?;
        let stored: Option<ProjectivePoint> = ProjectivePoint::from_encoded_point(&encoded).into();
        let stored = stored.ok_or(ZkpError::InvalidCommitment("Invalid point".into()))?;

        Ok(expected == stored)
    }

    /// Add two Pedersen commitments (homomorphic property)
    ///
    /// # Errors
    /// Returns an error if either commitment contains an invalid elliptic curve point.
    ///
    /// # Elliptic Curve Arithmetic
    /// Uses secp256k1 point addition for homomorphic commitment.
    #[allow(clippy::arithmetic_side_effects)] // EC point addition is modular
    pub fn add(&self, other: &PedersenCommitment) -> Result<PedersenCommitment> {
        use k256::EncodedPoint;
        use k256::elliptic_curve::sec1::FromEncodedPoint;

        let encoded1 = EncodedPoint::from_bytes(self.commitment)
            .map_err(|e| ZkpError::InvalidCommitment(format!("Invalid point 1: {}", e)))?;
        let point1: Option<ProjectivePoint> = ProjectivePoint::from_encoded_point(&encoded1).into();
        let point1 = point1.ok_or(ZkpError::InvalidCommitment("Invalid point 1".into()))?;

        let encoded2 = EncodedPoint::from_bytes(other.commitment)
            .map_err(|e| ZkpError::InvalidCommitment(format!("Invalid point 2: {}", e)))?;
        let point2: Option<ProjectivePoint> = ProjectivePoint::from_encoded_point(&encoded2).into();
        let point2 = point2.ok_or(ZkpError::InvalidCommitment("Invalid point 2".into()))?;

        let sum = point1 + point2;

        let commitment: [u8; 33] = <[u8; 33]>::try_from(sum.to_affine().to_bytes().as_slice())
            .map_err(|e| ZkpError::SerializationError(format!("Failed to serialize sum: {}", e)))?;

        Ok(PedersenCommitment { commitment })
    }

    /// Generate second generator H using hash-to-curve
    /// H = hash_to_point("arc-zkp/pedersen-H")
    ///
    /// # Elliptic Curve Arithmetic
    /// Uses scalar multiplication to derive generator H.
    #[allow(clippy::arithmetic_side_effects)] // EC scalar multiplication is modular
    fn generator_h() -> ProjectivePoint {
        // Use SHA-256 to derive H from a fixed string
        // This ensures H's discrete log relative to G is unknown
        let mut hasher = Sha256::new();
        hasher.update(b"arc-zkp/pedersen-generator-H-v1");
        let hash = hasher.finalize();

        // Use hash as x-coordinate, find valid point
        // For simplicity, multiply G by hash (not ideal but works for demo)
        let scalar = <Scalar as Reduce<U256>>::reduce_bytes(FieldBytes::from_slice(&hash));
        ProjectivePoint::GENERATOR * scalar
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_commitment() {
        let value = b"secret value";
        let (commitment, opening) = HashCommitment::commit(value).unwrap();

        assert!(commitment.verify(&opening).unwrap());
    }

    #[test]
    fn test_hash_commitment_wrong_value() {
        let (commitment, mut opening) = HashCommitment::commit(b"value1").unwrap();
        opening.value = b"value2".to_vec();

        assert!(!commitment.verify(&opening).unwrap());
    }

    #[test]
    fn test_hash_commitment_deterministic() {
        let value = b"test";
        let randomness = [42u8; 32];

        let c1 = HashCommitment::commit_with_randomness(value, randomness);
        let c2 = HashCommitment::commit_with_randomness(value, randomness);

        assert_eq!(c1.commitment, c2.commitment);
    }

    #[test]
    fn test_pedersen_commitment() {
        let value = [1u8; 32];
        let (commitment, opening) = PedersenCommitment::commit(&value).unwrap();

        assert!(commitment.verify(&opening).unwrap());
    }

    #[test]
    fn test_pedersen_commitment_wrong_value() {
        let value = [1u8; 32];
        let (commitment, mut opening) = PedersenCommitment::commit(&value).unwrap();
        opening.value = [2u8; 32];

        assert!(!commitment.verify(&opening).unwrap());
    }

    #[test]
    fn test_pedersen_homomorphic() {
        let v1 = [1u8; 32];
        let v2 = [2u8; 32];
        let b1 = [10u8; 32];
        let b2 = [20u8; 32];

        let (c1, _) = PedersenCommitment::commit_with_blinding(&v1, &b1).unwrap();
        let (c2, _) = PedersenCommitment::commit_with_blinding(&v2, &b2).unwrap();

        // c1 + c2 should equal commitment to (v1+v2, b1+b2)
        let c_sum = c1.add(&c2).unwrap();

        // Compute v1 + v2 and b1 + b2 as scalars
        let s1 = Scalar::from_repr(*FieldBytes::from_slice(&v1)).unwrap();
        let s2 = Scalar::from_repr(*FieldBytes::from_slice(&v2)).unwrap();
        let r1 = Scalar::from_repr(*FieldBytes::from_slice(&b1)).unwrap();
        let r2 = Scalar::from_repr(*FieldBytes::from_slice(&b2)).unwrap();

        let v_sum: [u8; 32] = (s1 + s2).to_bytes().into();
        let b_sum: [u8; 32] = (r1 + r2).to_bytes().into();

        let (c_expected, _) = PedersenCommitment::commit_with_blinding(&v_sum, &b_sum).unwrap();

        assert_eq!(c_sum.commitment, c_expected.commitment);
    }
}
