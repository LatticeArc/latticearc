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

use crate::primitives::hash::sha2::sha256;
use crate::zkp::error::{Result, ZkpError};
use k256::elliptic_curve::{PrimeField, ops::Reduce};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A sigma protocol proof (non-interactive via Fiat-Shamir)
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
#[cfg_attr(feature = "zkp-serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SigmaProof {
    /// Commitment (first message)
    commitment: Vec<u8>,
    /// Challenge (derived via Fiat-Shamir)
    challenge: [u8; 32],
    /// Response (third message)
    response: Vec<u8>,
}

impl SigmaProof {
    /// Construct a proof from its constituent parts.
    #[must_use]
    pub fn new(commitment: Vec<u8>, challenge: [u8; 32], response: Vec<u8>) -> Self {
        Self { commitment, challenge, response }
    }

    /// Return a reference to the commitment bytes (first message).
    #[must_use]
    pub fn commitment(&self) -> &[u8] {
        &self.commitment
    }

    /// Return a reference to the Fiat-Shamir challenge bytes.
    #[must_use]
    pub fn challenge(&self) -> &[u8; 32] {
        &self.challenge
    }

    /// Return a reference to the response bytes (third message).
    #[must_use]
    pub fn response(&self) -> &[u8] {
        &self.response
    }

    /// Return a mutable reference to the challenge bytes.
    ///
    /// Intended for test tampering scenarios only.
    #[must_use]
    pub fn challenge_mut(&mut self) -> &mut [u8; 32] {
        &mut self.challenge
    }
}

impl std::fmt::Debug for SigmaProof {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigmaProof")
            .field("commitment", &format!("[{} bytes]", self.commitment.len()))
            .field("challenge", &"[REDACTED]")
            .field("response", &"[REDACTED]")
            .finish()
    }
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
    #[must_use]
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
        let challenge = self.compute_challenge(statement, &commitment_bytes, context)?;

        // Step 3: Generate response
        let response = self.protocol.respond(witness, commit_state, &challenge)?;
        let response_bytes = self.protocol.serialize_response(&response);

        Ok(SigmaProof::new(commitment_bytes, challenge, response_bytes))
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
        let expected_challenge = self.compute_challenge(statement, proof.commitment(), context)?;

        // Constant-time challenge comparison to prevent timing side-channels
        if expected_challenge.ct_eq(proof.challenge()).unwrap_u8() == 0 {
            return Ok(false);
        }

        // Deserialize and verify
        let commitment = self.protocol.deserialize_commitment(proof.commitment())?;
        let response = self.protocol.deserialize_response(proof.response())?;

        self.protocol.verify(statement, &commitment, proof.challenge(), &response)
    }

    /// Compute Fiat-Shamir challenge
    ///
    /// # Safety
    /// Uses saturating conversion for length encoding. ZKP data is always
    /// small enough to fit in u32, but we use saturating_cast for safety.
    ///
    /// # Errors
    /// Returns an error if the SHA-256 primitive fails (input exceeds 1 GiB guard).
    fn compute_challenge(
        &self,
        statement: &P::Statement,
        commitment: &[u8],
        context: &[u8],
    ) -> Result<[u8; 32]> {
        // Accumulate into a buffer and route through the primitives wrapper
        // so hash backends remain swappable in one place.
        let statement_bytes = self.protocol.serialize_statement(statement);
        let statement_len = u32::try_from(statement_bytes.len()).unwrap_or(u32::MAX);
        let commitment_len = u32::try_from(commitment.len()).unwrap_or(u32::MAX);
        let context_len = u32::try_from(context.len()).unwrap_or(u32::MAX);

        let mut buf = Vec::with_capacity(
            self.domain_separator
                .len()
                .saturating_add(4)
                .saturating_add(statement_bytes.len())
                .saturating_add(4)
                .saturating_add(commitment.len())
                .saturating_add(4)
                .saturating_add(context.len()),
        );
        buf.extend_from_slice(&self.domain_separator);
        buf.extend_from_slice(&statement_len.to_le_bytes());
        buf.extend_from_slice(&statement_bytes);
        buf.extend_from_slice(&commitment_len.to_le_bytes());
        buf.extend_from_slice(commitment);
        buf.extend_from_slice(&context_len.to_le_bytes());
        buf.extend_from_slice(context);

        // ZKP payloads are always well below the 1 GiB SHA-256 DoS cap.
        sha256(&buf).map_err(|e| ZkpError::SerializationError(format!("SHA-256 failed: {}", e)))
    }
}

// ============================================================================
// Example: Discrete Log Equality Proof
// ============================================================================

/// Proof that two discrete logs are equal
/// Given (G, H, P, Q), prove knowledge of x such that P = x*G and Q = x*H
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct DlogEqualityProof {
    /// First commitment A = k*G
    /// Consumer: verify(), a()
    a: [u8; 33],
    /// Second commitment B = k*H
    /// Consumer: verify(), b()
    b: [u8; 33],
    /// Challenge
    /// Consumer: verify(), challenge()
    challenge: [u8; 32],
    /// Response s = k + c*x
    /// Consumer: verify(), response()
    response: [u8; 32],
}

impl DlogEqualityProof {
    /// Construct a proof from raw field bytes.
    ///
    /// This is intended for deserialization and testing. Callers are responsible
    /// for ensuring the bytes represent a valid proof.
    #[must_use]
    pub fn new(a: [u8; 33], b: [u8; 33], challenge: [u8; 32], response: [u8; 32]) -> Self {
        Self { a, b, challenge, response }
    }

    /// Return the first commitment bytes A = k*G (compressed, 33 bytes).
    #[must_use]
    pub fn a(&self) -> &[u8; 33] {
        &self.a
    }

    /// Return the second commitment bytes B = k*H (compressed, 33 bytes).
    #[must_use]
    pub fn b(&self) -> &[u8; 33] {
        &self.b
    }

    /// Return the Fiat-Shamir challenge bytes (32 bytes).
    #[must_use]
    pub fn challenge(&self) -> &[u8; 32] {
        &self.challenge
    }

    /// Return the response scalar bytes s = k + c*x (32 bytes).
    #[must_use]
    pub fn response(&self) -> &[u8; 32] {
        &self.response
    }
}

impl std::fmt::Debug for DlogEqualityProof {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DlogEqualityProof")
            .field("a", &self.a)
            .field("b", &self.b)
            .field("challenge", &"[REDACTED]")
            .field("response", &"[REDACTED]")
            .finish()
    }
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
            elliptic_curve::{group::GroupEncoding, ops::Reduce},
        };

        // Parse generators
        let g = Self::parse_point(&statement.g)?;
        let h = Self::parse_point(&statement.h)?;

        // Parse secret
        let x: Option<Scalar> = Scalar::from_repr(*FieldBytes::from_slice(secret)).into();
        let x = x.ok_or(ZkpError::InvalidScalar)?;

        // Random nonce via primitives layer
        let nonce_bytes = crate::primitives::rand::csprng::random_bytes(32);
        let k = <Scalar as Reduce<k256::U256>>::reduce_bytes(k256::FieldBytes::from_slice(
            &nonce_bytes,
        ));

        // Commitments
        let a_point = g * k;
        let b_point = h * k;

        let a_bytes: [u8; 33] = <[u8; 33]>::try_from(a_point.to_affine().to_bytes().as_slice())
            .map_err(|e| ZkpError::SerializationError(format!("Failed to serialize A: {}", e)))?;
        let b_bytes: [u8; 33] = <[u8; 33]>::try_from(b_point.to_affine().to_bytes().as_slice())
            .map_err(|e| ZkpError::SerializationError(format!("Failed to serialize B: {}", e)))?;

        // Challenge
        let challenge = Self::compute_challenge(statement, &a_bytes, &b_bytes, context)?;
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

        // Constant-time challenge comparison to prevent timing side-channels
        let expected_challenge = Self::compute_challenge(statement, &self.a, &self.b, context)?;
        if expected_challenge.ct_eq(&self.challenge).unwrap_u8() == 0 {
            return Ok(false);
        }

        // Parse response and challenge
        let s: Option<Scalar> = Scalar::from_repr(*FieldBytes::from_slice(&self.response)).into();
        let s = s.ok_or(ZkpError::InvalidScalar)?;
        let c =
            <Scalar as Reduce<k256::U256>>::reduce_bytes(FieldBytes::from_slice(&self.challenge));

        // Verify: s*G == A + c*P and s*H == B + c*Q (constant-time comparison)
        let lhs1 = g * s;
        let rhs1 = a + p * c;

        let lhs2 = h * s;
        let rhs2 = b + q * c;

        // Use bitwise AND to avoid short-circuit evaluation
        Ok(bool::from(lhs1.ct_eq(&rhs1)) & bool::from(lhs2.ct_eq(&rhs2)))
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

    /// # Errors
    /// Returns an error if the SHA-256 primitive fails (input exceeds 1 GiB guard).
    fn compute_challenge(
        statement: &DlogEqualityStatement,
        a: &[u8; 33],
        b: &[u8; 33],
        context: &[u8],
    ) -> Result<[u8; 32]> {
        // Accumulate into a buffer and route through the primitives wrapper
        // so hash backends remain swappable in one place.
        let label = b"arc-zkp/dlog-equality-v1";
        let mut buf = Vec::with_capacity(
            label.len().saturating_add(33 * 4).saturating_add(33 * 2).saturating_add(context.len()),
        );
        buf.extend_from_slice(label);
        buf.extend_from_slice(&statement.g);
        buf.extend_from_slice(&statement.h);
        buf.extend_from_slice(&statement.p);
        buf.extend_from_slice(&statement.q);
        buf.extend_from_slice(a);
        buf.extend_from_slice(b);
        buf.extend_from_slice(context);

        // 200 bytes of compressed points and labels — well below SHA-256 DoS cap.
        sha256(&buf).map_err(|e| ZkpError::SerializationError(format!("SHA-256 failed: {}", e)))
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
    fn test_dlog_equality_proof_succeeds() {
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
    fn test_dlog_equality_wrong_context_fails_verification_fails() {
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

    #[test]
    fn test_dlog_equality_wrong_secret_fails_verification_fails() {
        // Prove with one secret, verify with a statement that uses a different discrete log
        let x_key = SecretKey::random(&mut rand::thread_rng());
        let x: [u8; 32] = x_key.to_bytes().into();
        let x_scalar = Scalar::from_repr(*FieldBytes::from_slice(&x)).unwrap();

        let y_key = SecretKey::random(&mut rand::thread_rng());
        let y: [u8; 32] = y_key.to_bytes().into();
        let y_scalar = Scalar::from_repr(*FieldBytes::from_slice(&y)).unwrap();

        let g = ProjectivePoint::GENERATOR;
        let h = g * Scalar::from(3u64);

        // Statement uses x for G but y for H (different discrete logs)
        let p = g * x_scalar; // P = x*G
        let q = h * y_scalar; // Q = y*H (should be x*H for valid proof)

        let g_bytes: [u8; 33] = <[u8; 33]>::try_from(g.to_affine().to_bytes().as_slice()).unwrap();
        let h_bytes: [u8; 33] = <[u8; 33]>::try_from(h.to_affine().to_bytes().as_slice()).unwrap();
        let p_bytes: [u8; 33] = <[u8; 33]>::try_from(p.to_affine().to_bytes().as_slice()).unwrap();
        let q_bytes: [u8; 33] = <[u8; 33]>::try_from(q.to_affine().to_bytes().as_slice()).unwrap();

        let statement = DlogEqualityStatement { g: g_bytes, h: h_bytes, p: p_bytes, q: q_bytes };

        // Proving with x: P = x*G is fine but Q != x*H
        let proof = DlogEqualityProof::prove(&statement, &x, b"test").unwrap();
        // Verification should fail since the discrete logs are not equal
        assert!(!proof.verify(&statement, b"test").unwrap());
    }

    #[test]
    fn test_dlog_equality_tampered_challenge_fails_verification_fails() {
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

        let mut proof = DlogEqualityProof::prove(&statement, &x, b"test").unwrap();
        // Tamper with challenge
        proof.challenge[0] ^= 0xFF;
        assert!(!proof.verify(&statement, b"test").unwrap());
    }

    #[test]
    fn test_dlog_equality_tampered_response_fails_verification_fails() {
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

        let mut proof = DlogEqualityProof::prove(&statement, &x, b"test").unwrap();
        // Tamper with response
        proof.response[0] ^= 0xFF;
        // Should fail verification (either false or error for invalid scalar)
        let result = proof.verify(&statement, b"test");
        if let Ok(valid) = result {
            assert!(!valid);
        }
        // Err case: invalid scalar is also acceptable
    }

    #[test]
    fn test_dlog_equality_invalid_point_returns_error() {
        // Use invalid SEC1 prefix byte (must be 0x02 or 0x03 for compressed)
        let mut invalid_point: [u8; 33] = [0x05; 33]; // Invalid prefix
        invalid_point[0] = 0x05;
        let valid_g: [u8; 33] =
            <[u8; 33]>::try_from(ProjectivePoint::GENERATOR.to_affine().to_bytes().as_slice())
                .unwrap();

        let statement =
            DlogEqualityStatement { g: invalid_point, h: valid_g, p: valid_g, q: valid_g };

        let secret = [1u8; 32];
        let result = DlogEqualityProof::prove(&statement, &secret, b"test");
        assert!(result.is_err());
    }

    #[test]
    fn test_dlog_equality_proof_fields_are_populated_succeeds() {
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

        let proof = DlogEqualityProof::prove(&statement, &x, b"test").unwrap();

        // Proof fields should be populated
        assert_eq!(proof.a.len(), 33);
        assert_eq!(proof.b.len(), 33);
        assert_eq!(proof.challenge.len(), 32);
        assert_eq!(proof.response.len(), 32);

        // Clone and debug
        let proof2 = proof.clone();
        assert_eq!(proof.challenge, proof2.challenge);
        let debug = format!("{:?}", proof);
        assert!(debug.contains("DlogEqualityProof"));
    }

    #[test]
    fn test_dlog_equality_statement_clone_debug_succeeds() {
        let g: [u8; 33] =
            <[u8; 33]>::try_from(ProjectivePoint::GENERATOR.to_affine().to_bytes().as_slice())
                .unwrap();

        let statement = DlogEqualityStatement { g, h: g, p: g, q: g };
        let stmt2 = statement.clone();
        assert_eq!(statement.g, stmt2.g);

        let debug = format!("{:?}", statement);
        assert!(debug.contains("DlogEqualityStatement"));
    }

    #[test]
    fn test_sigma_proof_fields_are_populated_succeeds() {
        let proof = SigmaProof::new(vec![1, 2, 3], [0u8; 32], vec![4, 5, 6]);
        let proof2 = proof.clone();
        assert_eq!(proof.commitment(), proof2.commitment());
        assert_eq!(proof.challenge(), proof2.challenge());
        assert_eq!(proof.response(), proof2.response());

        let debug = format!("{:?}", proof);
        assert!(debug.contains("SigmaProof"));
    }

    #[test]
    fn test_dlog_equality_different_generators_succeeds() {
        // Use a different multiplier for H
        let secret_key = SecretKey::random(&mut rand::thread_rng());
        let x: [u8; 32] = secret_key.to_bytes().into();
        let x_scalar = Scalar::from_repr(*FieldBytes::from_slice(&x)).unwrap();

        let g = ProjectivePoint::GENERATOR;
        let h = g * Scalar::from(7u64); // H = 7*G

        let p = g * x_scalar;
        let q = h * x_scalar;

        let g_bytes: [u8; 33] = <[u8; 33]>::try_from(g.to_affine().to_bytes().as_slice()).unwrap();
        let h_bytes: [u8; 33] = <[u8; 33]>::try_from(h.to_affine().to_bytes().as_slice()).unwrap();
        let p_bytes: [u8; 33] = <[u8; 33]>::try_from(p.to_affine().to_bytes().as_slice()).unwrap();
        let q_bytes: [u8; 33] = <[u8; 33]>::try_from(q.to_affine().to_bytes().as_slice()).unwrap();

        let statement = DlogEqualityStatement { g: g_bytes, h: h_bytes, p: p_bytes, q: q_bytes };

        let proof = DlogEqualityProof::prove(&statement, &x, b"ctx").unwrap();
        assert!(proof.verify(&statement, b"ctx").unwrap());
    }

    // ========================================================================
    // FiatShamir wrapper tests
    // ========================================================================

    /// Minimal sigma protocol mock for testing FiatShamir wrapper
    struct MockSigmaProtocol;

    impl SigmaProtocol for MockSigmaProtocol {
        type Statement = Vec<u8>;
        type Witness = Vec<u8>;
        type Commitment = Vec<u8>;
        type Response = Vec<u8>;

        fn commit(
            &self,
            _statement: &Self::Statement,
            witness: &Self::Witness,
        ) -> Result<(Self::Commitment, Vec<u8>)> {
            // Deterministic commitment: hash of witness
            let mut buf = Vec::with_capacity(b"mock-commit".len() + witness.len());
            buf.extend_from_slice(b"mock-commit");
            buf.extend_from_slice(witness);
            let commitment = sha256(&buf).unwrap().to_vec();
            // State = copy of witness for respond()
            Ok((commitment, witness.clone()))
        }

        fn respond(
            &self,
            _witness: &Self::Witness,
            commitment_state: Vec<u8>,
            challenge: &[u8; 32],
        ) -> Result<Self::Response> {
            // Response: hash(commitment_state || challenge)
            let mut buf = Vec::with_capacity(
                b"mock-response".len() + commitment_state.len() + challenge.len(),
            );
            buf.extend_from_slice(b"mock-response");
            buf.extend_from_slice(&commitment_state);
            buf.extend_from_slice(challenge);
            Ok(sha256(&buf).unwrap().to_vec())
        }

        fn verify(
            &self,
            _statement: &Self::Statement,
            commitment: &Self::Commitment,
            challenge: &[u8; 32],
            response: &Self::Response,
        ) -> Result<bool> {
            // For mock: verify that response matches expected hash
            // We can't reconstruct witness, so just check lengths are valid
            Ok(commitment.len() == 32 && challenge.len() == 32 && response.len() == 32)
        }

        fn serialize_commitment(&self, commitment: &Self::Commitment) -> Vec<u8> {
            commitment.clone()
        }

        fn deserialize_commitment(&self, bytes: &[u8]) -> Result<Self::Commitment> {
            Ok(bytes.to_vec())
        }

        fn serialize_response(&self, response: &Self::Response) -> Vec<u8> {
            response.clone()
        }

        fn deserialize_response(&self, bytes: &[u8]) -> Result<Self::Response> {
            Ok(bytes.to_vec())
        }

        fn serialize_statement(&self, statement: &Self::Statement) -> Vec<u8> {
            statement.clone()
        }
    }

    #[test]
    fn test_fiat_shamir_prove_verify_roundtrip_succeeds() {
        let fs = FiatShamir::new(MockSigmaProtocol, b"test-domain");
        let statement = vec![1u8; 32];
        let witness = vec![42u8; 16];

        let proof = fs.prove(&statement, &witness, b"context").unwrap();

        // Proof fields should be populated
        assert_eq!(proof.commitment().len(), 32);
        assert_eq!(proof.challenge().len(), 32);
        assert_eq!(proof.response().len(), 32);

        // Verification should succeed
        assert!(fs.verify(&statement, &proof, b"context").unwrap());
    }

    #[test]
    fn test_fiat_shamir_wrong_context_fails() {
        let fs = FiatShamir::new(MockSigmaProtocol, b"test-domain");
        let statement = vec![1u8; 32];
        let witness = vec![42u8; 16];

        let proof = fs.prove(&statement, &witness, b"context-a").unwrap();

        // Different context → different challenge → verification fails
        assert!(!fs.verify(&statement, &proof, b"context-b").unwrap());
    }

    #[test]
    fn test_fiat_shamir_tampered_challenge_fails() {
        let fs = FiatShamir::new(MockSigmaProtocol, b"test-domain");
        let statement = vec![1u8; 32];
        let witness = vec![42u8; 16];

        let mut proof = fs.prove(&statement, &witness, b"ctx").unwrap();
        proof.challenge_mut()[0] ^= 0xFF; // Tamper with challenge

        // Recomputed challenge won't match tampered one
        assert!(!fs.verify(&statement, &proof, b"ctx").unwrap());
    }

    #[test]
    fn test_fiat_shamir_different_domain_separators_produce_different_proofs_succeeds() {
        let fs1 = FiatShamir::new(MockSigmaProtocol, b"domain-1");
        let fs2 = FiatShamir::new(MockSigmaProtocol, b"domain-2");
        let statement = vec![1u8; 32];
        let witness = vec![42u8; 16];

        let proof = fs1.prove(&statement, &witness, b"ctx").unwrap();

        // Proof from domain-1 should not verify under domain-2
        assert!(!fs2.verify(&statement, &proof, b"ctx").unwrap());
    }

    #[test]
    fn test_fiat_shamir_different_statements_produce_different_proofs_succeeds() {
        let fs = FiatShamir::new(MockSigmaProtocol, b"domain");
        let statement1 = vec![1u8; 32];
        let statement2 = vec![2u8; 32];
        let witness = vec![42u8; 16];

        let proof = fs.prove(&statement1, &witness, b"ctx").unwrap();

        // Proof for statement1 should not verify under statement2
        assert!(!fs.verify(&statement2, &proof, b"ctx").unwrap());
    }

    #[test]
    fn test_fiat_shamir_empty_domain_and_context_succeeds() {
        let fs = FiatShamir::new(MockSigmaProtocol, b"");
        let statement = vec![0u8; 32];
        let witness = vec![0u8; 8];

        let proof = fs.prove(&statement, &witness, b"").unwrap();
        assert!(fs.verify(&statement, &proof, b"").unwrap());
    }

    #[test]
    fn test_dlog_equality_empty_context_succeeds() {
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

        let proof = DlogEqualityProof::prove(&statement, &x, b"").unwrap();
        assert!(proof.verify(&statement, b"").unwrap());
    }
}
