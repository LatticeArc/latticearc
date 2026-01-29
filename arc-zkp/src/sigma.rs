//! Sigma Protocols
//!
//! Generic framework for sigma protocols (3-round public-coin proofs).
//! Provides Fiat-Shamir transformation for non-interactive proofs.
//!
//! ## Structure
//!
//! A sigma protocol consists of:
//! 1. **Commitment**: Prover sends commitment A
//! 2. **Challenge**: Verifier sends random challenge c (or derived via Fiat-Shamir)
//! 3. **Response**: Prover sends response z
//!
//! ## Properties
//!
//! - Special soundness: Given two accepting transcripts with same A, extract witness
//! - Honest-verifier zero-knowledge: Simulator can produce indistinguishable transcripts

use crate::error::{Result, ZkpError};
use k256::elliptic_curve::{PrimeField, ops::Reduce};
use sha2::{Digest, Sha256};

/// A sigma protocol proof (non-interactive via Fiat-Shamir)
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SigmaProof {
    /// Commitment (first message)
    pub commitment: Vec<u8>,
    /// Challenge (derived via Fiat-Shamir)
    pub challenge: [u8; 32],
    /// Response (third message)
    pub response: Vec<u8>,
}

/// Trait for implementing sigma protocols
pub trait SigmaProtocol {
    /// Statement type (what we're proving)
    type Statement;
    /// Witness type (the secret)
    type Witness;
    /// Commitment type
    type Commitment;
    /// Response type
    type Response;

    /// Generate commitment (step 1)
    ///
    /// # Errors
    /// Returns an error if commitment generation fails.
    fn commit(
        &self,
        statement: &Self::Statement,
        witness: &Self::Witness,
    ) -> Result<(Self::Commitment, Vec<u8>)>;

    /// Generate response given challenge (step 3)
    ///
    /// # Errors
    /// Returns an error if response computation fails.
    fn respond(
        &self,
        witness: &Self::Witness,
        commitment_state: Vec<u8>,
        challenge: &[u8; 32],
    ) -> Result<Self::Response>;

    /// Verify the proof
    ///
    /// # Errors
    /// Returns an error if proof verification fails due to invalid data.
    fn verify(
        &self,
        statement: &Self::Statement,
        commitment: &Self::Commitment,
        challenge: &[u8; 32],
        response: &Self::Response,
    ) -> Result<bool>;

    /// Serialize commitment for Fiat-Shamir
    fn serialize_commitment(&self, commitment: &Self::Commitment) -> Vec<u8>;

    /// Deserialize commitment
    ///
    /// # Errors
    /// Returns an error if the bytes do not represent a valid commitment.
    fn deserialize_commitment(&self, bytes: &[u8]) -> Result<Self::Commitment>;

    /// Serialize response
    fn serialize_response(&self, response: &Self::Response) -> Vec<u8>;

    /// Deserialize response
    ///
    /// # Errors
    /// Returns an error if the bytes do not represent a valid response.
    fn deserialize_response(&self, bytes: &[u8]) -> Result<Self::Response>;

    /// Serialize statement for challenge computation
    fn serialize_statement(&self, statement: &Self::Statement) -> Vec<u8>;
}

/// Fiat-Shamir transformed sigma protocol
pub struct FiatShamir<P: SigmaProtocol> {
    protocol: P,
    domain_separator: Vec<u8>,
}

impl<P: SigmaProtocol> FiatShamir<P> {
    /// Create a new Fiat-Shamir wrapper
    pub fn new(protocol: P, domain_separator: &[u8]) -> Self {
        Self { protocol, domain_separator: domain_separator.to_vec() }
    }

    /// Generate a non-interactive proof
    ///
    /// # Errors
    /// Returns an error if commitment generation or response computation fails.
    pub fn prove(
        &self,
        statement: &P::Statement,
        witness: &P::Witness,
        context: &[u8],
    ) -> Result<SigmaProof> {
        // Step 1: Generate commitment
        let (commitment, commit_state) = self.protocol.commit(statement, witness)?;
        let commitment_bytes = self.protocol.serialize_commitment(&commitment);

        // Step 2: Compute Fiat-Shamir challenge
        let challenge = self.compute_challenge(statement, &commitment_bytes, context);

        // Step 3: Generate response
        let response = self.protocol.respond(witness, commit_state, &challenge)?;
        let response_bytes = self.protocol.serialize_response(&response);

        Ok(SigmaProof { commitment: commitment_bytes, challenge, response: response_bytes })
    }

    /// Verify a non-interactive proof
    ///
    /// # Errors
    /// Returns an error if proof deserialization or verification fails.
    pub fn verify(
        &self,
        statement: &P::Statement,
        proof: &SigmaProof,
        context: &[u8],
    ) -> Result<bool> {
        // Recompute challenge
        let expected_challenge = self.compute_challenge(statement, &proof.commitment, context);

        // Check challenge matches
        if expected_challenge != proof.challenge {
            return Ok(false);
        }

        // Deserialize and verify
        let commitment = self.protocol.deserialize_commitment(&proof.commitment)?;
        let response = self.protocol.deserialize_response(&proof.response)?;

        self.protocol.verify(statement, &commitment, &proof.challenge, &response)
    }

    /// Compute Fiat-Shamir challenge
    ///
    /// # Safety
    /// Uses saturating conversion for length encoding. ZKP data is always
    /// small enough to fit in u32, but we use saturating_cast for safety.
    fn compute_challenge(
        &self,
        statement: &P::Statement,
        commitment: &[u8],
        context: &[u8],
    ) -> [u8; 32] {
        let mut hasher = Sha256::new();

        // Domain separation
        hasher.update(&self.domain_separator);

        // Statement - use saturating conversion (ZKP data is always small)
        let statement_bytes = self.protocol.serialize_statement(statement);
        let statement_len = u32::try_from(statement_bytes.len()).unwrap_or(u32::MAX);
        hasher.update(statement_len.to_le_bytes());
        hasher.update(&statement_bytes);

        // Commitment
        let commitment_len = u32::try_from(commitment.len()).unwrap_or(u32::MAX);
        hasher.update(commitment_len.to_le_bytes());
        hasher.update(commitment);

        // Context
        let context_len = u32::try_from(context.len()).unwrap_or(u32::MAX);
        hasher.update(context_len.to_le_bytes());
        hasher.update(context);

        hasher.finalize().into()
    }
}

// ============================================================================
// Example: Discrete Log Equality Proof
// ============================================================================

/// Proof that two discrete logs are equal
/// Given (G, H, P, Q), prove knowledge of x such that P = x*G and Q = x*H
#[derive(Debug, Clone)]
pub struct DlogEqualityProof {
    /// First commitment A = k*G
    pub a: [u8; 33],
    /// Second commitment B = k*H
    pub b: [u8; 33],
    /// Challenge
    pub challenge: [u8; 32],
    /// Response s = k + c*x
    pub response: [u8; 32],
}

/// Statement for discrete log equality
#[derive(Debug, Clone)]
pub struct DlogEqualityStatement {
    /// Generator G
    pub g: [u8; 33],
    /// Generator H
    pub h: [u8; 33],
    /// P = x*G
    pub p: [u8; 33],
    /// Q = x*H
    pub q: [u8; 33],
}

impl DlogEqualityProof {
    /// Create a proof of discrete log equality
    ///
    /// # Errors
    /// Returns an error if point parsing fails or the secret is invalid.
    ///
    /// # Elliptic Curve Arithmetic
    /// Uses secp256k1 scalar and point operations. These are modular
    /// arithmetic in a finite field that cannot overflow.
    #[allow(clippy::arithmetic_side_effects)] // EC math is modular, cannot overflow
    pub fn prove(
        statement: &DlogEqualityStatement,
        secret: &[u8; 32],
        context: &[u8],
    ) -> Result<Self> {
        use k256::{
            FieldBytes, Scalar,
            elliptic_curve::{Field, group::GroupEncoding},
        };

        // Parse generators
        let g = Self::parse_point(&statement.g)?;
        let h = Self::parse_point(&statement.h)?;

        // Parse secret
        let x: Option<Scalar> = Scalar::from_repr(*FieldBytes::from_slice(secret)).into();
        let x = x.ok_or(ZkpError::InvalidScalar)?;

        // Random nonce
        let k = Scalar::random(&mut rand::thread_rng());

        // Commitments
        let a_point = g * k;
        let b_point = h * k;

        let a_bytes: [u8; 33] = <[u8; 33]>::try_from(a_point.to_affine().to_bytes().as_slice())
            .map_err(|e| ZkpError::SerializationError(format!("Failed to serialize A: {}", e)))?;
        let b_bytes: [u8; 33] = <[u8; 33]>::try_from(b_point.to_affine().to_bytes().as_slice())
            .map_err(|e| ZkpError::SerializationError(format!("Failed to serialize B: {}", e)))?;

        // Challenge
        let challenge = Self::compute_challenge(statement, &a_bytes, &b_bytes, context);
        let c = <Scalar as Reduce<k256::U256>>::reduce_bytes(FieldBytes::from_slice(&challenge));

        // Response
        let s = k + c * x;
        let response: [u8; 32] = s.to_bytes().into();

        Ok(Self { a: a_bytes, b: b_bytes, challenge, response })
    }

    /// Verify a discrete log equality proof
    ///
    /// # Errors
    /// Returns an error if point parsing fails or the response scalar is invalid.
    ///
    /// # Elliptic Curve Arithmetic
    /// Uses secp256k1 scalar and point operations for verification.
    #[allow(clippy::arithmetic_side_effects)] // EC math is modular, cannot overflow
    pub fn verify(&self, statement: &DlogEqualityStatement, context: &[u8]) -> Result<bool> {
        use k256::{FieldBytes, Scalar};

        // Parse points
        let g = Self::parse_point(&statement.g)?;
        let h = Self::parse_point(&statement.h)?;
        let p = Self::parse_point(&statement.p)?;
        let q = Self::parse_point(&statement.q)?;
        let a = Self::parse_point(&self.a)?;
        let b = Self::parse_point(&self.b)?;

        // Verify challenge
        let expected_challenge = Self::compute_challenge(statement, &self.a, &self.b, context);
        if expected_challenge != self.challenge {
            return Ok(false);
        }

        // Parse response and challenge
        let s: Option<Scalar> = Scalar::from_repr(*FieldBytes::from_slice(&self.response)).into();
        let s = s.ok_or(ZkpError::InvalidScalar)?;
        let c =
            <Scalar as Reduce<k256::U256>>::reduce_bytes(FieldBytes::from_slice(&self.challenge));

        // Verify: s*G == A + c*P and s*H == B + c*Q
        let lhs1 = g * s;
        let rhs1 = a + p * c;

        let lhs2 = h * s;
        let rhs2 = b + q * c;

        Ok(lhs1 == rhs1 && lhs2 == rhs2)
    }

    fn parse_point(bytes: &[u8; 33]) -> Result<k256::ProjectivePoint> {
        use k256::EncodedPoint;
        use k256::elliptic_curve::sec1::FromEncodedPoint;

        let encoded = EncodedPoint::from_bytes(bytes)
            .map_err(|e| ZkpError::SerializationError(format!("Invalid point encoding: {}", e)))?;
        let point: Option<k256::ProjectivePoint> =
            k256::ProjectivePoint::from_encoded_point(&encoded).into();
        point.ok_or(ZkpError::InvalidPublicKey)
    }

    fn compute_challenge(
        statement: &DlogEqualityStatement,
        a: &[u8; 33],
        b: &[u8; 33],
        context: &[u8],
    ) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"arc-zkp/dlog-equality-v1");
        hasher.update(statement.g);
        hasher.update(statement.h);
        hasher.update(statement.p);
        hasher.update(statement.q);
        hasher.update(a);
        hasher.update(b);
        hasher.update(context);
        hasher.finalize().into()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use k256::{
        FieldBytes, ProjectivePoint, Scalar, SecretKey, elliptic_curve::group::GroupEncoding,
    };

    #[test]
    fn test_dlog_equality_proof() {
        // Generate secret
        let secret_key = SecretKey::random(&mut rand::thread_rng());
        let x: [u8; 32] = secret_key.to_bytes().into();
        let x_scalar = Scalar::from_repr(*FieldBytes::from_slice(&x)).unwrap();

        // Two different generators
        let g = ProjectivePoint::GENERATOR;
        let h = g * Scalar::from(2u64); // H = 2*G for testing

        // Compute P = x*G and Q = x*H
        let p = g * x_scalar;
        let q = h * x_scalar;

        let g_bytes: [u8; 33] = <[u8; 33]>::try_from(g.to_affine().to_bytes().as_slice()).unwrap();
        let h_bytes: [u8; 33] = <[u8; 33]>::try_from(h.to_affine().to_bytes().as_slice()).unwrap();
        let p_bytes: [u8; 33] = <[u8; 33]>::try_from(p.to_affine().to_bytes().as_slice()).unwrap();
        let q_bytes: [u8; 33] = <[u8; 33]>::try_from(q.to_affine().to_bytes().as_slice()).unwrap();

        let statement = DlogEqualityStatement { g: g_bytes, h: h_bytes, p: p_bytes, q: q_bytes };

        let proof = DlogEqualityProof::prove(&statement, &x, b"test").unwrap();
        assert!(proof.verify(&statement, b"test").unwrap());
    }

    #[test]
    fn test_dlog_equality_wrong_context() {
        let secret_key = SecretKey::random(&mut rand::thread_rng());
        let x: [u8; 32] = secret_key.to_bytes().into();
        let x_scalar = Scalar::from_repr(*FieldBytes::from_slice(&x)).unwrap();

        let g = ProjectivePoint::GENERATOR;
        let h = g * Scalar::from(2u64);
        let p = g * x_scalar;
        let q = h * x_scalar;

        let g_bytes: [u8; 33] = <[u8; 33]>::try_from(g.to_affine().to_bytes().as_slice()).unwrap();
        let h_bytes: [u8; 33] = <[u8; 33]>::try_from(h.to_affine().to_bytes().as_slice()).unwrap();
        let p_bytes: [u8; 33] = <[u8; 33]>::try_from(p.to_affine().to_bytes().as_slice()).unwrap();
        let q_bytes: [u8; 33] = <[u8; 33]>::try_from(q.to_affine().to_bytes().as_slice()).unwrap();

        let statement = DlogEqualityStatement { g: g_bytes, h: h_bytes, p: p_bytes, q: q_bytes };

        let proof = DlogEqualityProof::prove(&statement, &x, b"context1").unwrap();
        assert!(!proof.verify(&statement, b"context2").unwrap());
    }
}
