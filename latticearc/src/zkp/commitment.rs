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

use crate::primitives::hash::{sha2::sha256, sha3::sha3_256};
use crate::zkp::error::{Result, ZkpError};
use k256::{
    FieldBytes, ProjectivePoint, Scalar,
    elliptic_curve::{PrimeField, group::GroupEncoding, sec1::ToEncodedPoint},
};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

// ============================================================================
// Hash Commitment
// ============================================================================

/// Simple hash-based commitment scheme
///
/// Commitment: C = H(value || randomness)
/// Opening: reveal value and randomness, verify C == H(value || randomness)
#[derive(Debug, Clone)]
#[cfg_attr(feature = "zkp-serde", derive(serde::Serialize, serde::Deserialize))]
pub struct HashCommitment {
    /// The commitment hash
    /// Consumer: verify(), commit_with_randomness(), test_hash_commitment_hiding(), test_schnorr_and_hash_commitment_together()
    commitment: [u8; 32],
}

/// Opening for a hash commitment
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct HashOpening {
    /// The committed value
    /// Consumer: verify()
    value: Vec<u8>,
    /// The randomness used
    /// Consumer: verify()
    randomness: [u8; 32],
}

impl std::fmt::Debug for HashOpening {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HashOpening").field("data", &"[REDACTED]").finish()
    }
}

impl ConstantTimeEq for HashOpening {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.value.as_slice().ct_eq(other.value.as_slice())
            & self.randomness.ct_eq(&other.randomness)
    }
}

impl HashOpening {
    /// Create a new hash opening with the given value and randomness.
    #[must_use]
    pub fn new(value: Vec<u8>, randomness: [u8; 32]) -> Self {
        Self { value, randomness }
    }

    /// Return the committed value.
    #[must_use]
    pub fn value(&self) -> &[u8] {
        &self.value
    }

    /// Return the randomness used during commitment.
    #[must_use]
    pub fn randomness(&self) -> &[u8; 32] {
        &self.randomness
    }
}

impl HashCommitment {
    /// Create a new hash commitment to a value
    ///
    /// # Errors
    /// Returns an error if random number generation fails.
    pub fn commit(value: &[u8]) -> Result<(Self, HashOpening)> {
        let rand_vec = crate::primitives::rand::csprng::random_bytes(32);
        let mut randomness = [0u8; 32];
        randomness.copy_from_slice(&rand_vec);

        let commitment = Self::compute_hash(value, &randomness);

        Ok((Self { commitment }, HashOpening::new(value.to_vec(), randomness)))
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
        let expected = Self::compute_hash(opening.value(), opening.randomness());
        Ok(self.commitment.ct_eq(&expected).into())
    }

    /// Return the raw commitment hash bytes.
    #[must_use]
    pub fn commitment(&self) -> &[u8; 32] {
        &self.commitment
    }

    /// Compute H(value || randomness)
    fn compute_hash(value: &[u8], randomness: &[u8; 32]) -> [u8; 32] {
        // Accumulate all inputs into a single buffer and route through the
        // primitives wrapper so hash backends stay swappable in one place.
        let mut buf = Vec::with_capacity(
            b"arc-zkp/hash-commitment-v1"
                .len()
                .saturating_add(8)
                .saturating_add(value.len())
                .saturating_add(randomness.len()),
        );
        buf.extend_from_slice(b"arc-zkp/hash-commitment-v1");
        buf.extend_from_slice(&(value.len() as u64).to_le_bytes());
        buf.extend_from_slice(value);
        buf.extend_from_slice(randomness);
        sha3_256(&buf)
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
#[cfg_attr(feature = "zkp-serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "zkp-serde", serde(crate = "serde"))]
pub struct PedersenCommitment {
    /// The commitment point (compressed)
    /// Consumer: verify(), add(), commitment()
    #[cfg_attr(feature = "zkp-serde", serde(with = "serde_with::As::<serde_with::Bytes>"))]
    commitment: [u8; 33],
}

/// Opening for a Pedersen commitment
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PedersenOpening {
    /// The committed value (as scalar bytes)
    /// Consumer: verify()
    value: [u8; 32],
    /// The blinding factor
    /// Consumer: verify()
    blinding: [u8; 32],
}

impl std::fmt::Debug for PedersenOpening {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PedersenOpening").field("data", &"[REDACTED]").finish()
    }
}

impl ConstantTimeEq for PedersenOpening {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.value.ct_eq(&other.value) & self.blinding.ct_eq(&other.blinding)
    }
}

impl PedersenOpening {
    /// Create a new Pedersen opening with the given value and blinding factor.
    #[must_use]
    pub fn new(value: [u8; 32], blinding: [u8; 32]) -> Self {
        Self { value, blinding }
    }

    /// Return the committed scalar value bytes.
    #[must_use]
    pub fn value(&self) -> &[u8; 32] {
        &self.value
    }

    /// Return the blinding factor bytes.
    #[must_use]
    pub fn blinding(&self) -> &[u8; 32] {
        &self.blinding
    }
}

impl PedersenCommitment {
    /// Create a new Pedersen commitment to a scalar value
    ///
    /// # Errors
    /// Returns an error if the value is not a valid scalar.
    pub fn commit(value: &[u8; 32]) -> Result<(Self, PedersenOpening)> {
        let rand_vec = crate::primitives::rand::csprng::random_bytes(32);
        let mut blinding = [0u8; 32];
        blinding.copy_from_slice(&rand_vec);

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
        let h = Self::generator_h()?;

        let commitment_point = g * v + h * r;

        let commitment: [u8; 33] =
            <[u8; 33]>::try_from(commitment_point.to_affine().to_bytes().as_slice()).map_err(
                |e| ZkpError::SerializationError(format!("Failed to serialize commitment: {}", e)),
            )?;

        Ok((Self { commitment }, PedersenOpening::new(*value, *blinding)))
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
        let v: Option<Scalar> = Scalar::from_repr(*FieldBytes::from_slice(opening.value())).into();
        let r: Option<Scalar> =
            Scalar::from_repr(*FieldBytes::from_slice(opening.blinding())).into();

        let v = v.ok_or(ZkpError::InvalidScalar)?;
        let r = r.ok_or(ZkpError::InvalidScalar)?;

        // Recompute C = v*G + r*H
        let g = ProjectivePoint::GENERATOR;
        let h = Self::generator_h()?;
        let expected = g * v + h * r;

        // Parse stored commitment
        use k256::EncodedPoint;
        use k256::elliptic_curve::sec1::FromEncodedPoint;

        let encoded = EncodedPoint::from_bytes(self.commitment)
            .map_err(|e| ZkpError::InvalidCommitment(format!("Invalid point encoding: {}", e)))?;
        let stored: Option<ProjectivePoint> = ProjectivePoint::from_encoded_point(&encoded).into();
        let stored = stored.ok_or(ZkpError::InvalidCommitment("Invalid point".into()))?;

        let expected_bytes = expected.to_affine().to_encoded_point(true);
        let stored_bytes = stored.to_affine().to_encoded_point(true);
        Ok(bool::from(expected_bytes.as_bytes().ct_eq(stored_bytes.as_bytes())))
    }

    /// Return the raw commitment point bytes (compressed, 33 bytes).
    #[must_use]
    pub fn commitment(&self) -> &[u8; 33] {
        &self.commitment
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

        let encoded2 = EncodedPoint::from_bytes(other.commitment())
            .map_err(|e| ZkpError::InvalidCommitment(format!("Invalid point 2: {}", e)))?;
        let point2: Option<ProjectivePoint> = ProjectivePoint::from_encoded_point(&encoded2).into();
        let point2 = point2.ok_or(ZkpError::InvalidCommitment("Invalid point 2".into()))?;

        let sum = point1 + point2;

        let commitment: [u8; 33] = <[u8; 33]>::try_from(sum.to_affine().to_bytes().as_slice())
            .map_err(|e| ZkpError::SerializationError(format!("Failed to serialize sum: {}", e)))?;

        Ok(PedersenCommitment { commitment })
    }

    /// Generate second generator H via try-and-increment on SHA-256.
    ///
    /// Hashes `"arc-zkp/pedersen-generator-H-v2" || counter` for counter = 0, 1, ...
    /// until the 32-byte output is a valid compressed x-coordinate on secp256k1.
    /// The resulting point has no known discrete-log relationship to G, which is
    /// required for the binding property of Pedersen commitments.
    ///
    /// Cached after first computation via `OnceLock`.
    ///
    /// # Errors
    /// Returns an error if the SHA-256 primitive fails (input exceeds 1 GiB guard)
    /// or if no valid curve point is found within 256 iterations.
    fn generator_h() -> Result<ProjectivePoint> {
        use k256::EncodedPoint;
        use k256::elliptic_curve::sec1::FromEncodedPoint;

        static H: std::sync::OnceLock<ProjectivePoint> = std::sync::OnceLock::new();

        if let Some(cached) = H.get() {
            return Ok(*cached);
        }

        // Try-and-increment: hash with incrementing counter until we hit a valid point.
        // ~50% of random x-coords are valid on secp256k1, so this exits on the first
        // or second iteration with overwhelming probability.
        for counter in 0u32..256 {
            // Accumulate into a buffer and route through the primitives wrapper
            // so hash backends remain swappable in one place.
            let mut buf =
                Vec::with_capacity(b"arc-zkp/pedersen-generator-H-v2".len().saturating_add(4));
            buf.extend_from_slice(b"arc-zkp/pedersen-generator-H-v2");
            #[allow(clippy::arithmetic_side_effects)] // counter.to_le_bytes() is infallible
            buf.extend_from_slice(&counter.to_le_bytes());
            // Input is 34 bytes (30-byte label + 4-byte counter), well below the
            // 1 GiB SHA-256 DoS cap.
            let hash = sha256(&buf)
                .map_err(|e| ZkpError::SerializationError(format!("SHA-256 failed: {}", e)))?;

            let mut compressed = [0u8; 33];
            compressed[0] = 0x02;
            compressed[1..33].copy_from_slice(&hash);

            if let Ok(encoded) = EncodedPoint::from_bytes(compressed) {
                let point: Option<ProjectivePoint> =
                    ProjectivePoint::from_encoded_point(&encoded).into();
                if let Some(p) = point {
                    // Best-effort cache: a concurrent thread may have already set this.
                    let _ = H.set(p);
                    return Ok(p);
                }
            }
        }

        // Mathematically unreachable: P(all 256 fail) = (1/2)^256 ≈ 10^-77.
        Err(ZkpError::SerializationError(
            "Pedersen generator H derivation failed after 256 attempts".into(),
        ))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_commitment_succeeds() {
        let value = b"secret value";
        let (commitment, opening) = HashCommitment::commit(value).unwrap();

        assert!(commitment.verify(&opening).unwrap());
    }

    #[test]
    fn test_hash_commitment_wrong_value_fails() {
        let (commitment, mut opening) = HashCommitment::commit(b"value1").unwrap();
        opening.value = b"value2".to_vec();

        assert!(!commitment.verify(&opening).unwrap());
    }

    #[test]
    fn test_hash_commitment_wrong_randomness_fails() {
        let value = b"test value";
        let (commitment, opening) = HashCommitment::commit(value).unwrap();

        // Tamper with randomness
        let mut wrong_randomness = *opening.randomness();
        wrong_randomness[0] ^= 0xFF;
        let wrong_opening = HashOpening::new(opening.value().to_vec(), wrong_randomness);

        let result = commitment.verify(&wrong_opening).unwrap();
        assert!(!result, "Verification should fail with wrong randomness");
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
    fn test_pedersen_commitment_roundtrip_succeeds() {
        let value = [1u8; 32];
        let (commitment, opening) = PedersenCommitment::commit(&value).unwrap();

        assert!(commitment.verify(&opening).unwrap());
    }

    #[test]
    fn test_pedersen_commitment_wrong_value_fails() {
        let value = [1u8; 32];
        let (commitment, mut opening) = PedersenCommitment::commit(&value).unwrap();
        opening.value = [2u8; 32];

        assert!(!commitment.verify(&opening).unwrap());
    }

    #[test]
    fn test_pedersen_homomorphic_addition_matches_expected() {
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
