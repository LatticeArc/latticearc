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
///
/// # Cloning
///
/// `SigmaProof` deliberately does NOT implement `Clone`. When duplication is
/// genuinely needed for transmission to a verifier, use
/// [`SigmaProof::clone_for_transmission`] — each call is a deliberate,
/// grep-able audit checkpoint.
#[derive(Zeroize, ZeroizeOnDrop)]
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

    /// Make an independent copy of this proof for transmission to a verifier.
    #[must_use]
    pub fn clone_for_transmission(&self) -> Self {
        Self {
            commitment: self.commitment.clone(),
            challenge: self.challenge,
            response: self.response.clone(),
        }
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
    /// Intended for test tampering scenarios only — exposing this
    /// mutator on the production API surface lets a downstream caller
    /// replace the Fiat-Shamir challenge in a constructed proof without
    /// re-deriving the response, defeating soundness. Round-10 audit fix
    /// #11 gates it behind `#[cfg(any(test, feature = "test-utils"))]`.
    #[must_use]
    #[cfg(any(test, feature = "test-utils"))]
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

impl ConstantTimeEq for SigmaProof {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.commitment.ct_eq(&other.commitment)
            & self.challenge.ct_eq(&other.challenge)
            & self.response.ct_eq(&other.response)
    }
}

/// Sealed-trait pattern (Pattern 4) for [`SigmaProtocol`].
///
/// `SigmaProtocol` defines `commit` / `respond` / `verify` for zero-knowledge
/// proofs. An external implementor whose `verify` always returned `Ok(true)`
/// would silently pass-through any proof. Seal to prevent this.
mod sealed {
    pub trait Sealed {}
}

/// Trait for implementing sigma protocols.
///
/// Sealed (Pattern 4): only types in this crate can implement it. Adding a
/// new impl in this crate requires also implementing `sealed::Sealed`.
pub trait SigmaProtocol: sealed::Sealed {
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
    /// Create a new Fiat-Shamir wrapper.
    ///
    /// # Errors
    ///
    /// Returns [`ZkpError::InvalidDomainSeparator`] if `domain_separator`
    /// is empty. The Fiat-Shamir transform's challenge is
    /// `H(domain_separator || statement || commitment || context)`;
    /// without a non-empty domain separator, two distinct protocols that
    /// happen to share the same statement / commitment shape can produce
    /// colliding challenges, defeating the cross-protocol separation
    /// the wrapper is supposed to provide.
    pub fn new(protocol: P, domain_separator: &[u8]) -> Result<Self> {
        if domain_separator.is_empty() {
            return Err(ZkpError::InvalidDomainSeparator);
        }
        Ok(Self { protocol, domain_separator: domain_separator.to_vec() })
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
        // collapse all adversary-reachable
        // sub-errors (challenge hash failure, malformed commitment,
        // malformed response) to `Err(VerificationFailed)` so a probing
        // attacker cannot distinguish reject reasons from the Result
        // shape. Previously, `?` propagated the upstream error variants
        // directly while a legitimate challenge mismatch returned
        // `Ok(false)` — the variant difference was itself a
        // distinguisher.
        let expected_challenge =
            self.compute_challenge(statement, proof.commitment(), context).map_err(|e| {
                tracing::debug!(error = ?e, "FiatShamir::verify rejected: challenge hash");
                ZkpError::VerificationFailed
            })?;

        // Constant-time challenge comparison to prevent timing side-channels
        if expected_challenge.ct_eq(proof.challenge()).unwrap_u8() == 0 {
            return Ok(false);
        }

        // Deserialize and verify
        let commitment = self.protocol.deserialize_commitment(proof.commitment()).map_err(|e| {
            tracing::debug!(error = ?e, "FiatShamir::verify rejected: commitment deserialize");
            ZkpError::VerificationFailed
        })?;
        let response = self.protocol.deserialize_response(proof.response()).map_err(|e| {
            tracing::debug!(error = ?e, "FiatShamir::verify rejected: response deserialize");
            ZkpError::VerificationFailed
        })?;

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
        // previously these used
        // `unwrap_or(u32::MAX)` which silently saturated on a 4 GiB+
        // input, producing the same length-prefix bytes for any input
        // at or above 4 GiB and breaking transcript collision-
        // resistance. Practically unreachable today (SHA-256 has its
        // own 1 GiB DoS cap below) but a silent failure mode is worse
        // than an explicit error. Map to a Fiat-Shamir-specific Err
        // so reviewers can see the bound is enforced.
        let statement_len = u32::try_from(statement_bytes.len()).map_err(|_| {
            ZkpError::InvalidInput("Fiat-Shamir: statement exceeds 2^32 bytes".into())
        })?;
        let commitment_len = u32::try_from(commitment.len()).map_err(|_| {
            ZkpError::InvalidInput("Fiat-Shamir: commitment exceeds 2^32 bytes".into())
        })?;
        let context_len = u32::try_from(context.len()).map_err(|_| {
            ZkpError::InvalidInput("Fiat-Shamir: context exceeds 2^32 bytes".into())
        })?;

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
        // Length prefixes are big-endian to match the hybrid-layer
        // transcript constructors (`hybrid::kem_hybrid`,
        // `hybrid::encrypt_hybrid`). Note that `zkp::commitment` uses
        // its own domain-separated transcripts that retain a different
        // byte order for historical compatibility — they don't intermix
        // with the Fiat-Shamir transcript here.
        buf.extend_from_slice(&self.domain_separator);
        buf.extend_from_slice(&statement_len.to_be_bytes());
        buf.extend_from_slice(&statement_bytes);
        buf.extend_from_slice(&commitment_len.to_be_bytes());
        buf.extend_from_slice(commitment);
        buf.extend_from_slice(&context_len.to_be_bytes());
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
///
/// # Cloning
///
/// `DlogEqualityProof` deliberately does NOT implement `Clone`. When duplication
/// is genuinely needed for transmission to a verifier, use
/// [`DlogEqualityProof::clone_for_transmission`] — each call is a deliberate,
/// grep-able audit checkpoint.
#[derive(Zeroize, ZeroizeOnDrop)]
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

    /// Make an independent copy of this proof for transmission to a verifier.
    #[must_use]
    pub fn clone_for_transmission(&self) -> Self {
        Self { a: self.a, b: self.b, challenge: self.challenge, response: self.response }
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
            .field("a", &"[REDACTED]")
            .field("b", &"[REDACTED]")
            .field("challenge", &"[REDACTED]")
            .field("response", &"[REDACTED]")
            .finish()
    }
}

impl ConstantTimeEq for DlogEqualityProof {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.a.ct_eq(&other.a)
            & self.b.ct_eq(&other.b)
            & self.challenge.ct_eq(&other.challenge)
            & self.response.ct_eq(&other.response)
    }
}

/// Statement for discrete log equality.
///
/// the `g` and `h` fields remain `pub` for source-compat
/// with existing callers, but **prove() and verify() now reject any
/// statement whose `g` is not the canonical secp256k1 generator and
/// whose `h` is not the NUMS-derived point used by Pedersen commitments**.
/// Discrete-log-equality is sound only when the bases are independent
/// and trusted: a peer-supplied `(g, h)` with `h = g^x` for known `x`
/// makes the proof trivially forgeable. Locking the bases at the
/// prove/verify boundary prevents any caller (intentional or
/// adversarial) from supplying their own.
///
/// Use [`Self::canonical`] for new code — it fills in the canonical
/// bases automatically. The struct-literal form remains supported but
/// will fail prove/verify unless the bases match.
#[derive(Debug, Clone)]
pub struct DlogEqualityStatement {
    /// Generator G — must equal the canonical secp256k1 generator.
    pub g: [u8; 33],
    /// Generator H — must equal the Pedersen NUMS H point.
    pub h: [u8; 33],
    /// P = x*G
    pub p: [u8; 33],
    /// Q = x*H
    pub q: [u8; 33],
}

impl DlogEqualityStatement {
    /// canonical-base constructor. Returns a statement
    /// pre-filled with `g = secp256k1 generator` and
    /// `h = PedersenCommitment::generator_h()`. This is the only
    /// constructor whose result is guaranteed to pass the round-29
    /// base-canonicity check on prove/verify.
    ///
    /// # Errors
    /// Returns [`ZkpError::SerializationError`] if the NUMS H
    /// derivation fails (extremely rare — would require >256
    /// hash-to-curve iterations all hitting invalid x-coords).
    pub fn canonical(p: [u8; 33], q: [u8; 33]) -> Result<Self> {
        use k256::{ProjectivePoint, elliptic_curve::group::GroupEncoding};
        let g_point = ProjectivePoint::GENERATOR;
        let g_bytes: [u8; 33] = <[u8; 33]>::try_from(g_point.to_affine().to_bytes().as_slice())
            .map_err(|e| {
                ZkpError::SerializationError(format!("canonical G serialization: {}", e))
            })?;
        let h_point = crate::zkp::commitment::PedersenCommitment::generator_h()?;
        let h_bytes: [u8; 33] = <[u8; 33]>::try_from(h_point.to_affine().to_bytes().as_slice())
            .map_err(|e| {
                ZkpError::SerializationError(format!("canonical H serialization: {}", e))
            })?;
        Ok(Self { g: g_bytes, h: h_bytes, p, q })
    }

    /// returns the canonical (g, h) base pair as
    /// SEC1 compressed bytes. Used by prove/verify to validate that a
    /// supplied statement's `g` and `h` match the trusted bases.
    pub(crate) fn canonical_bases() -> Result<([u8; 33], [u8; 33])> {
        use k256::{ProjectivePoint, elliptic_curve::group::GroupEncoding};
        let g_bytes: [u8; 33] =
            <[u8; 33]>::try_from(ProjectivePoint::GENERATOR.to_affine().to_bytes().as_slice())
                .map_err(|e| {
                    ZkpError::SerializationError(format!("canonical G serialization: {}", e))
                })?;
        let h_point = crate::zkp::commitment::PedersenCommitment::generator_h()?;
        let h_bytes: [u8; 33] = <[u8; 33]>::try_from(h_point.to_affine().to_bytes().as_slice())
            .map_err(|e| {
                ZkpError::SerializationError(format!("canonical H serialization: {}", e))
            })?;
        Ok((g_bytes, h_bytes))
    }
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
            FieldBytes, Scalar, U256,
            elliptic_curve::{group::GroupEncoding, ops::Reduce},
        };

        // enforce that the statement's bases are the
        // canonical (G, NUMS H) pair. A caller supplying arbitrary
        // bases — or a peer-supplied statement with `h = g^x` for a
        // known `x` — would otherwise yield a trivially-forgeable
        // proof. Reject up-front; opaque error matches the round-26
        // H11 verify-side posture.
        let (canonical_g, canonical_h) = DlogEqualityStatement::canonical_bases()?;
        if statement.g != canonical_g || statement.h != canonical_h {
            tracing::debug!(
                "DlogEqualityProof::prove rejected: statement bases not canonical (round-29 M7)"
            );
            return Err(ZkpError::InvalidScalar);
        }

        // Parse generators
        let g = Self::parse_point(&statement.g)?;
        let h = Self::parse_point(&statement.h)?;

        // wrap scalars in `Zeroizing` so
        // stack-resident copies of `k`, `x`, and `s` (computed below)
        // are scrubbed when the function returns. See the matching
        // comment in `zkp/schnorr.rs::Schnorr::prove`.
        use zeroize::Zeroizing;

        // Parse secret
        let x: Option<Scalar> = Scalar::from_repr(*FieldBytes::from_slice(secret)).into();
        let x = Zeroizing::new(x.ok_or(ZkpError::InvalidScalar)?);

        // rejection sampling for the nonce — see matching
        // comment in `zkp/schnorr.rs::Schnorr::prove`. `Scalar::from_repr`
        // returns `None` for byte representations `>= q`, eliminating the
        // ~2^-128 modular bias of the previous `Reduce<U256>::reduce_bytes`
        // path. Loop terminates in 1 + ε iterations on average. Also
        // rejects k = 0.
        let k_scalar: Scalar = loop {
            let nonce_bytes = Zeroizing::new(crate::primitives::rand::csprng::random_bytes(32));
            let candidate: Option<Scalar> =
                Scalar::from_repr(*FieldBytes::from_slice(&nonce_bytes)).into();
            if let Some(s) = candidate {
                if s != Scalar::ZERO {
                    break s;
                }
            }
        };
        let k = Zeroizing::new(k_scalar);

        // Commitments
        let a_point = g * *k;
        let b_point = h * *k;

        let a_bytes: [u8; 33] = <[u8; 33]>::try_from(a_point.to_affine().to_bytes().as_slice())
            .map_err(|e| ZkpError::SerializationError(format!("Failed to serialize A: {}", e)))?;
        let b_bytes: [u8; 33] = <[u8; 33]>::try_from(b_point.to_affine().to_bytes().as_slice())
            .map_err(|e| ZkpError::SerializationError(format!("Failed to serialize B: {}", e)))?;

        // Challenge
        let challenge = Self::compute_challenge(statement, &a_bytes, &b_bytes, context)?;
        let c = <Scalar as Reduce<U256>>::reduce_bytes(FieldBytes::from_slice(&challenge));

        // Response
        let s = Zeroizing::new(*k + c * *x);
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
        use k256::{FieldBytes, Scalar, U256};

        // enforce canonical bases (mirror of `prove`).
        // Mismatch collapses to `Err(VerificationFailed)` per the
        // round-26 H11 Pattern 6 posture — not distinguishable from
        // any other reject cause via the Result shape.
        match DlogEqualityStatement::canonical_bases() {
            Ok((canonical_g, canonical_h)) => {
                if statement.g != canonical_g || statement.h != canonical_h {
                    tracing::debug!(
                        "DlogEqualityProof::verify rejected: statement bases not canonical (round-29 M7)"
                    );
                    return Err(ZkpError::VerificationFailed);
                }
            }
            Err(_) => {
                tracing::debug!(
                    "DlogEqualityProof::verify rejected: canonical-base derivation failed"
                );
                return Err(ZkpError::VerificationFailed);
            }
        }

        // collapse all adversary-reachable
        // sub-errors (off-curve points, out-of-field scalar, hash
        // serialization) to `Err(VerificationFailed)` so a probing
        // attacker cannot distinguish reject reasons from the Result
        // shape. Previously, `parse_point` returned `InvalidPublicKey`
        // / `SerializationError` and `Scalar::from_repr` returned
        // `InvalidScalar`, while a legitimate challenge mismatch
        // returned `Ok(false)` — the variant difference itself was a
        // distinguisher. The underlying cause is logged via
        // `tracing::debug!` for operators.
        let parse_or_fail = |result: Result<k256::ProjectivePoint>| {
            result.map_err(|e| {
                tracing::debug!(error = ?e, "DlogEqualityProof::verify rejected: point parse");
                ZkpError::VerificationFailed
            })
        };
        let g = parse_or_fail(Self::parse_point(&statement.g))?;
        let h = parse_or_fail(Self::parse_point(&statement.h))?;
        let p = parse_or_fail(Self::parse_point(&statement.p))?;
        let q = parse_or_fail(Self::parse_point(&statement.q))?;
        let a = parse_or_fail(Self::parse_point(&self.a))?;
        let b = parse_or_fail(Self::parse_point(&self.b))?;

        // Constant-time challenge comparison to prevent timing side-channels
        let expected_challenge = Self::compute_challenge(statement, &self.a, &self.b, context)
            .map_err(|e| {
                tracing::debug!(error = ?e, "DlogEqualityProof::verify rejected: hash failure");
                ZkpError::VerificationFailed
            })?;
        if expected_challenge.ct_eq(&self.challenge).unwrap_u8() == 0 {
            return Ok(false);
        }

        // Parse response and challenge
        let s: Option<Scalar> = Scalar::from_repr(*FieldBytes::from_slice(&self.response)).into();
        let s = s.ok_or_else(|| {
            tracing::debug!("DlogEqualityProof::verify rejected: invalid scalar");
            ZkpError::VerificationFailed
        })?;
        let c = <Scalar as Reduce<U256>>::reduce_bytes(FieldBytes::from_slice(&self.challenge));

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
    use rand_core_0_6::OsRng;

    #[test]
    fn test_dlog_equality_proof_succeeds() {
        // Generate secret
        let secret_key = SecretKey::random(&mut OsRng);
        let x: [u8; 32] = secret_key.to_bytes().into();
        let x_scalar = Scalar::from_repr(*FieldBytes::from_slice(&x)).unwrap();

        // Two different generators
        let g = ProjectivePoint::GENERATOR;
        let h = crate::zkp::commitment::PedersenCommitment::generator_h().unwrap(); // H = 2*G for testing

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
        let secret_key = SecretKey::random(&mut OsRng);
        let x: [u8; 32] = secret_key.to_bytes().into();
        let x_scalar = Scalar::from_repr(*FieldBytes::from_slice(&x)).unwrap();

        let g = ProjectivePoint::GENERATOR;
        let h = crate::zkp::commitment::PedersenCommitment::generator_h().unwrap();
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
        let x_key = SecretKey::random(&mut OsRng);
        let x: [u8; 32] = x_key.to_bytes().into();
        let x_scalar = Scalar::from_repr(*FieldBytes::from_slice(&x)).unwrap();

        let y_key = SecretKey::random(&mut OsRng);
        let y: [u8; 32] = y_key.to_bytes().into();
        let y_scalar = Scalar::from_repr(*FieldBytes::from_slice(&y)).unwrap();

        let g = ProjectivePoint::GENERATOR;
        let h = crate::zkp::commitment::PedersenCommitment::generator_h().unwrap();

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
        let secret_key = SecretKey::random(&mut OsRng);
        let x: [u8; 32] = secret_key.to_bytes().into();
        let x_scalar = Scalar::from_repr(*FieldBytes::from_slice(&x)).unwrap();

        let g = ProjectivePoint::GENERATOR;
        let h = crate::zkp::commitment::PedersenCommitment::generator_h().unwrap();
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
        let secret_key = SecretKey::random(&mut OsRng);
        let x: [u8; 32] = secret_key.to_bytes().into();
        let x_scalar = Scalar::from_repr(*FieldBytes::from_slice(&x)).unwrap();

        let g = ProjectivePoint::GENERATOR;
        let h = crate::zkp::commitment::PedersenCommitment::generator_h().unwrap();
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
        let secret_key = SecretKey::random(&mut OsRng);
        let x: [u8; 32] = secret_key.to_bytes().into();
        let x_scalar = Scalar::from_repr(*FieldBytes::from_slice(&x)).unwrap();

        let g = ProjectivePoint::GENERATOR;
        let h = crate::zkp::commitment::PedersenCommitment::generator_h().unwrap();
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

        let proof2 = proof.clone_for_transmission();
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
        let proof2 = proof.clone_for_transmission();
        assert_eq!(proof.commitment(), proof2.commitment());
        assert_eq!(proof.challenge(), proof2.challenge());
        assert_eq!(proof.response(), proof2.response());

        let debug = format!("{:?}", proof);
        assert!(debug.contains("SigmaProof"));
    }

    #[test]
    fn test_dlog_equality_different_generators_succeeds() {
        // Use a different multiplier for H
        let secret_key = SecretKey::random(&mut OsRng);
        let x: [u8; 32] = secret_key.to_bytes().into();
        let x_scalar = Scalar::from_repr(*FieldBytes::from_slice(&x)).unwrap();

        let g = ProjectivePoint::GENERATOR;
        let h = crate::zkp::commitment::PedersenCommitment::generator_h().unwrap();

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

    impl sealed::Sealed for MockSigmaProtocol {}

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
            // Deterministic commitment: hash of witness.
            let mut buf = Vec::new();
            buf.extend_from_slice(b"mock-commit");
            buf.extend_from_slice(witness);
            let commitment = sha256(&buf)
                .map_err(|e| ZkpError::SerializationError(format!("SHA-256 failed: {e}")))?
                .to_vec();
            // Carry the commitment forward so `respond` and `verify` derive
            // the response from the same publicly-checkable input. (We
            // deliberately do NOT carry the witness into state — that
            // would make the mock's response unverifiable from public
            // data, which led the previous `verify` to a length-only
            // check that returned `Ok(true)` for any 32-byte input.)
            Ok((commitment.clone(), commitment))
        }

        fn respond(
            &self,
            _witness: &Self::Witness,
            commitment_state: Vec<u8>,
            challenge: &[u8; 32],
        ) -> Result<Self::Response> {
            // Response: hash("mock-response" || commitment || challenge).
            // `commitment_state == commitment` per `commit()` above.
            let mut buf = Vec::new();
            buf.extend_from_slice(b"mock-response");
            buf.extend_from_slice(&commitment_state);
            buf.extend_from_slice(challenge);
            let digest = sha256(&buf)
                .map_err(|e| ZkpError::SerializationError(format!("SHA-256 failed: {e}")))?;
            Ok(digest.to_vec())
        }

        fn verify(
            &self,
            _statement: &Self::Statement,
            commitment: &Self::Commitment,
            challenge: &[u8; 32],
            response: &Self::Response,
        ) -> Result<bool> {
            // Reconstruct the expected response from public data and
            // compare in constant time. A mock that returns `Ok(true)`
            // for any 32-byte input gives `FiatShamir` callers no
            // signal — round-10 audit fix #8 closes that gap.
            if commitment.len() != 32 || response.len() != 32 {
                return Ok(false);
            }
            let mut buf = Vec::new();
            buf.extend_from_slice(b"mock-response");
            buf.extend_from_slice(commitment);
            buf.extend_from_slice(challenge);
            let expected = sha256(&buf)
                .map_err(|e| ZkpError::SerializationError(format!("SHA-256 failed: {e}")))?;
            Ok(bool::from(response.ct_eq(expected.as_ref())))
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
        let fs = FiatShamir::new(MockSigmaProtocol, b"test-domain").unwrap();
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
        let fs = FiatShamir::new(MockSigmaProtocol, b"test-domain").unwrap();
        let statement = vec![1u8; 32];
        let witness = vec![42u8; 16];

        let proof = fs.prove(&statement, &witness, b"context-a").unwrap();

        // Different context → different challenge → verification fails
        assert!(!fs.verify(&statement, &proof, b"context-b").unwrap());
    }

    #[test]
    fn test_fiat_shamir_tampered_challenge_fails() {
        let fs = FiatShamir::new(MockSigmaProtocol, b"test-domain").unwrap();
        let statement = vec![1u8; 32];
        let witness = vec![42u8; 16];

        let mut proof = fs.prove(&statement, &witness, b"ctx").unwrap();
        proof.challenge_mut()[0] ^= 0xFF; // Tamper with challenge

        // Recomputed challenge won't match tampered one
        assert!(!fs.verify(&statement, &proof, b"ctx").unwrap());
    }

    #[test]
    fn test_fiat_shamir_different_domain_separators_produce_different_proofs_succeeds() {
        let fs1 = FiatShamir::new(MockSigmaProtocol, b"domain-1").unwrap();
        let fs2 = FiatShamir::new(MockSigmaProtocol, b"domain-2").unwrap();
        let statement = vec![1u8; 32];
        let witness = vec![42u8; 16];

        let proof = fs1.prove(&statement, &witness, b"ctx").unwrap();

        // Proof from domain-1 should not verify under domain-2
        assert!(!fs2.verify(&statement, &proof, b"ctx").unwrap());
    }

    #[test]
    fn test_fiat_shamir_different_statements_produce_different_proofs_succeeds() {
        let fs = FiatShamir::new(MockSigmaProtocol, b"domain").unwrap();
        let statement1 = vec![1u8; 32];
        let statement2 = vec![2u8; 32];
        let witness = vec![42u8; 16];

        let proof = fs.prove(&statement1, &witness, b"ctx").unwrap();

        // Proof for statement1 should not verify under statement2
        assert!(!fs.verify(&statement2, &proof, b"ctx").unwrap());
    }

    #[test]
    fn test_fiat_shamir_empty_domain_separator_rejected() {
        // Empty domain separator defeats cross-protocol challenge
        // separation; constructor must refuse it.
        let result = FiatShamir::new(MockSigmaProtocol, b"");
        assert!(matches!(result, Err(ZkpError::InvalidDomainSeparator)));
    }

    #[test]
    fn test_fiat_shamir_empty_context_succeeds() {
        // Empty `context` is fine — the domain separator carries the
        // cross-protocol uniqueness; per-call context is optional.
        let fs = FiatShamir::new(MockSigmaProtocol, b"empty-context-test").unwrap();
        let statement = vec![0u8; 32];
        let witness = vec![0u8; 8];

        let proof = fs.prove(&statement, &witness, b"").unwrap();
        assert!(fs.verify(&statement, &proof, b"").unwrap());
    }

    #[test]
    fn test_dlog_equality_empty_context_succeeds() {
        let secret_key = SecretKey::random(&mut OsRng);
        let x: [u8; 32] = secret_key.to_bytes().into();
        let x_scalar = Scalar::from_repr(*FieldBytes::from_slice(&x)).unwrap();

        let g = ProjectivePoint::GENERATOR;
        let h = crate::zkp::commitment::PedersenCommitment::generator_h().unwrap();
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

    // --- Clone + Zeroize acceptance tests (#50) ---
    //
    // Document that `Clone` on proof types is acceptable under the project
    // threat model: each clone has independent storage, and `ZeroizeOnDrop`
    // zeros each instance at end-of-scope. See SECURITY.md
    // ("ZKP Proof Clone Acceptance") for the full rationale.

    #[test]
    fn test_sigma_proof_clone_for_transmission_independent_storage() {
        let proof = SigmaProof::new(vec![0xAA; 48], [0xBB; 32], vec![0xCC; 48]);
        let mut cloned = proof.clone_for_transmission();
        Zeroize::zeroize(&mut cloned);
        assert_eq!(proof.commitment(), &[0xAA; 48]);
        assert_eq!(proof.challenge(), &[0xBB; 32]);
        assert_eq!(proof.response(), &[0xCC; 48]);
        // `Zeroize for Vec<u8>` wipes bytes then truncates to len 0, so the
        // observable post-condition for Vecs is empty length. The fixed-size
        // `challenge` is zeroized in-place.
        assert!(cloned.commitment().is_empty());
        assert_eq!(cloned.challenge(), &[0u8; 32]);
        assert!(cloned.response().is_empty());
    }

    #[test]
    fn test_sigma_proof_zeroize_wipes_all_fields() {
        let mut proof = SigmaProof::new(vec![0xAA; 48], [0xBB; 32], vec![0xCC; 48]);
        Zeroize::zeroize(&mut proof);
        assert!(proof.commitment().is_empty());
        assert_eq!(proof.challenge(), &[0u8; 32]);
        assert!(proof.response().is_empty());
    }

    #[test]
    fn test_dlog_equality_proof_clone_for_transmission_independent_storage() {
        let proof = DlogEqualityProof::new([0xAA; 33], [0xBB; 33], [0xCC; 32], [0xDD; 32]);
        let mut cloned = proof.clone_for_transmission();
        Zeroize::zeroize(&mut cloned);
        assert_eq!(*proof.a(), [0xAA; 33]);
        assert_eq!(*proof.b(), [0xBB; 33]);
        assert_eq!(*proof.challenge(), [0xCC; 32]);
        assert_eq!(*proof.response(), [0xDD; 32]);
        assert_eq!(*cloned.a(), [0u8; 33]);
        assert_eq!(*cloned.b(), [0u8; 33]);
        assert_eq!(*cloned.challenge(), [0u8; 32]);
        assert_eq!(*cloned.response(), [0u8; 32]);
    }

    #[test]
    fn test_dlog_equality_proof_zeroize_wipes_all_fields() {
        let mut proof = DlogEqualityProof::new([0xAA; 33], [0xBB; 33], [0xCC; 32], [0xDD; 32]);
        Zeroize::zeroize(&mut proof);
        assert_eq!(*proof.a(), [0u8; 33]);
        assert_eq!(*proof.b(), [0u8; 33]);
        assert_eq!(*proof.challenge(), [0u8; 32]);
        assert_eq!(*proof.response(), [0u8; 32]);
    }
}
