//! Schnorr Zero-Knowledge Proofs
//!
//! Implements Schnorr's protocol for proving knowledge of a discrete logarithm
//! without revealing the secret. Uses the Fiat-Shamir heuristic for non-interactive
//! proofs.
//!
//! ## Protocol
//!
//! Given generator G and public key P = x*G, prove knowledge of x:
//!
//! 1. Prover picks random k, computes R = k*G
//! 2. Challenge c = H(G || P || R || context)
//! 3. Response s = k + c*x
//! 4. Verifier checks: s*G == R + c*P
//!
//! ## Security
//!
//! - Uses secp256k1 curve (same as Bitcoin/Ethereum)
//! - SHA-256 for Fiat-Shamir challenge
//! - Constant-time operations where possible

use crate::error::{Result, ZkpError};
use k256::{
    FieldBytes, ProjectivePoint, Scalar, SecretKey, U256,
    elliptic_curve::{Field, PrimeField, group::GroupEncoding, ops::Reduce},
};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Schnorr proof structure
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "serde"))]
pub struct SchnorrProof {
    /// Commitment point R = k*G
    #[cfg_attr(feature = "serde", serde(with = "serde_with::As::<serde_with::Bytes>"))]
    pub commitment: [u8; 33],
    /// Response s = k + c*x
    #[cfg_attr(feature = "serde", serde(with = "serde_with::As::<serde_with::Bytes>"))]
    pub response: [u8; 32],
}

/// Schnorr prover (holds the secret)
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SchnorrProver {
    /// Secret key x
    secret: [u8; 32],
    /// Public key P = x*G (not sensitive)
    #[zeroize(skip)]
    public_key: [u8; 33],
}

impl SchnorrProver {
    /// Create a new Schnorr prover with a random secret key
    ///
    /// # Errors
    /// Returns an error if key serialization fails.
    pub fn new() -> Result<(Self, [u8; 33])> {
        let mut rng = rand::thread_rng();
        let secret_key = SecretKey::random(&mut rng);
        let public_key = secret_key.public_key();

        let secret_bytes: [u8; 32] = secret_key.to_bytes().into();
        let public_bytes: [u8; 33] = <[u8; 33]>::try_from(public_key.to_sec1_bytes().as_ref())
            .map_err(|e| {
                ZkpError::SerializationError(format!("Failed to serialize public key: {}", e))
            })?;

        let prover = Self { secret: secret_bytes, public_key: public_bytes };

        Ok((prover, public_bytes))
    }

    /// Create a prover from an existing secret key
    ///
    /// # Errors
    /// Returns an error if the secret key is invalid or serialization fails.
    pub fn from_secret(secret: &[u8; 32]) -> Result<(Self, [u8; 33])> {
        let secret_key = SecretKey::from_bytes(secret.into())
            .map_err(|e| ZkpError::SerializationError(format!("Invalid secret key: {}", e)))?;
        let public_key = secret_key.public_key();

        let public_bytes: [u8; 33] = <[u8; 33]>::try_from(public_key.to_sec1_bytes().as_ref())
            .map_err(|e| {
                ZkpError::SerializationError(format!("Failed to serialize public key: {}", e))
            })?;

        let prover = Self { secret: *secret, public_key: public_bytes };

        Ok((prover, public_bytes))
    }

    /// Generate a Schnorr proof (non-interactive via Fiat-Shamir)
    ///
    /// # Errors
    /// Returns an error if the secret key is invalid or point serialization fails.
    ///
    /// # Elliptic Curve Arithmetic
    /// Uses secp256k1 scalar operations for Schnorr proof generation.
    /// These are modular arithmetic in a finite field.
    #[allow(clippy::arithmetic_side_effects)] // EC scalar math is modular, cannot overflow
    pub fn prove(&self, context: &[u8]) -> Result<SchnorrProof> {
        let mut rng = rand::thread_rng();

        // Parse secret key
        let x: Option<Scalar> = Scalar::from_repr(*FieldBytes::from_slice(&self.secret)).into();
        let x = x.ok_or(ZkpError::InvalidScalar)?;

        // Generate random nonce k
        let k = Scalar::random(&mut rng);

        // Compute commitment R = k*G
        let r_point = ProjectivePoint::GENERATOR * k;
        let r_bytes: [u8; 33] = <[u8; 33]>::try_from(r_point.to_affine().to_bytes().as_slice())
            .map_err(|e| ZkpError::SerializationError(format!("Failed to serialize R: {}", e)))?;

        // Compute challenge c = H(G || P || R || context)
        let c = self.compute_challenge(&r_bytes, context);

        // Compute response s = k + c*x
        let s = k + c * x;
        let s_bytes: [u8; 32] = s.to_bytes().into();

        Ok(SchnorrProof { commitment: r_bytes, response: s_bytes })
    }

    /// Compute Fiat-Shamir challenge
    fn compute_challenge(&self, r_bytes: &[u8; 33], context: &[u8]) -> Scalar {
        let mut hasher = Sha256::new();

        // Domain separation
        hasher.update(b"arc-zkp/schnorr-v1");

        // Include generator (implicit - using secp256k1)
        hasher.update(b"secp256k1");

        // Include public key
        hasher.update(self.public_key);

        // Include commitment
        hasher.update(r_bytes);

        // Include context
        hasher.update(context);

        let hash = hasher.finalize();
        <Scalar as Reduce<U256>>::reduce_bytes(FieldBytes::from_slice(&hash))
    }

    /// Get the public key
    #[must_use]
    pub fn public_key(&self) -> &[u8; 33] {
        &self.public_key
    }
}

/// Schnorr verifier (only knows public key)
pub struct SchnorrVerifier {
    /// Public key P
    public_key: [u8; 33],
}

impl SchnorrVerifier {
    /// Create a new verifier for a given public key
    #[must_use]
    pub fn new(public_key: [u8; 33]) -> Self {
        Self { public_key }
    }

    /// Verify a Schnorr proof
    ///
    /// # Errors
    /// Returns an error if the public key, commitment, or response is invalid.
    ///
    /// # Elliptic Curve Arithmetic
    /// Uses secp256k1 scalar and point operations for verification.
    /// These are modular arithmetic in a finite field.
    #[allow(clippy::arithmetic_side_effects)] // EC math is modular, cannot overflow
    pub fn verify(&self, proof: &SchnorrProof, context: &[u8]) -> Result<bool> {
        // Parse public key P
        let p_point = Self::parse_point(&self.public_key)?;

        // Parse commitment R
        let r_point = Self::parse_point(&proof.commitment)?;

        // Parse response s
        let s: Option<Scalar> = Scalar::from_repr(*FieldBytes::from_slice(&proof.response)).into();
        let s = s.ok_or(ZkpError::InvalidScalar)?;

        // Compute challenge c = H(G || P || R || context)
        let c = self.compute_challenge(&proof.commitment, context);

        // Verify: s*G == R + c*P
        let lhs = ProjectivePoint::GENERATOR * s;
        let rhs = r_point + p_point * c;

        Ok(lhs == rhs)
    }

    /// Parse a compressed point
    fn parse_point(bytes: &[u8; 33]) -> Result<ProjectivePoint> {
        use k256::EncodedPoint;
        use k256::elliptic_curve::sec1::FromEncodedPoint;

        let encoded = EncodedPoint::from_bytes(bytes)
            .map_err(|e| ZkpError::SerializationError(format!("Invalid point encoding: {}", e)))?;
        let point: Option<ProjectivePoint> = ProjectivePoint::from_encoded_point(&encoded).into();
        point.ok_or(ZkpError::InvalidPublicKey)
    }

    /// Compute Fiat-Shamir challenge
    fn compute_challenge(&self, r_bytes: &[u8; 33], context: &[u8]) -> Scalar {
        let mut hasher = Sha256::new();

        // Domain separation
        hasher.update(b"arc-zkp/schnorr-v1");

        // Include generator (implicit - using secp256k1)
        hasher.update(b"secp256k1");

        // Include public key
        hasher.update(self.public_key);

        // Include commitment
        hasher.update(r_bytes);

        // Include context
        hasher.update(context);

        let hash = hasher.finalize();
        <Scalar as Reduce<U256>>::reduce_bytes(FieldBytes::from_slice(&hash))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_schnorr_proof_valid() {
        let (prover, public_key) = SchnorrProver::new().unwrap();
        let context = b"test challenge context";

        let proof = prover.prove(context).unwrap();

        let verifier = SchnorrVerifier::new(public_key);
        assert!(verifier.verify(&proof, context).unwrap());
    }

    #[test]
    fn test_schnorr_proof_wrong_context() {
        let (prover, public_key) = SchnorrProver::new().unwrap();

        let proof = prover.prove(b"context 1").unwrap();

        let verifier = SchnorrVerifier::new(public_key);
        assert!(!verifier.verify(&proof, b"context 2").unwrap());
    }

    #[test]
    fn test_schnorr_proof_wrong_public_key() {
        let (prover, _) = SchnorrProver::new().unwrap();
        let (_, other_public_key) = SchnorrProver::new().unwrap();

        let context = b"test";
        let proof = prover.prove(context).unwrap();

        let verifier = SchnorrVerifier::new(other_public_key);
        assert!(!verifier.verify(&proof, context).unwrap());
    }

    #[test]
    fn test_schnorr_from_secret() {
        let secret = [42u8; 32];
        let (prover1, pk1) = SchnorrProver::from_secret(&secret).unwrap();
        let (_prover2, pk2) = SchnorrProver::from_secret(&secret).unwrap();

        assert_eq!(pk1, pk2);

        let proof = prover1.prove(b"test").unwrap();
        let verifier = SchnorrVerifier::new(pk2);
        assert!(verifier.verify(&proof, b"test").unwrap());
    }
}
