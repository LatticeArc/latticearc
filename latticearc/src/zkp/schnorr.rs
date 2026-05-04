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
//! - **Nonce k is generated fresh from `OsRng` on every call to `prove()`**
//!
//! # Warning: Nonce Reuse is Catastrophic
//!
//! If the same nonce `k` is ever used with the same secret key `x` for two
//! different challenges `c1` and `c2`, an attacker can recover `x`:
//!
//! ```text
//! s1 = k + c1*x,  s2 = k + c2*x
//! s1 - s2 = (c1 - c2)*x  →  x = (s1 - s2) / (c1 - c2)
//! ```
//!
//! This implementation prevents nonce reuse by generating `k` from the OS
//! CSPRNG (`OsRng`) on every proof. **Never modify `prove()` to accept an
//! external nonce or to cache/reuse nonces.**

use crate::primitives::hash::sha2::sha256;
use crate::zkp::error::{Result, ZkpError};
use k256::{
    FieldBytes, ProjectivePoint, Scalar, SecretKey, U256,
    elliptic_curve::{PrimeField, group::GroupEncoding, ops::Reduce},
};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Compute Fiat-Shamir challenge: `H("arc-zkp/schnorr-v1" || "secp256k1" || pk || R || ctx)`
///
/// # Errors
/// Returns an error if the SHA-256 primitive fails (input exceeds 1 GiB guard).
fn fiat_shamir_challenge(
    public_key: &[u8; 33],
    r_bytes: &[u8; 33],
    context: &[u8],
) -> Result<Scalar> {
    // Accumulate into a buffer and route through the primitives wrapper
    // so hash backends remain swappable in one place.
    let label = b"arc-zkp/schnorr-v1";
    let curve = b"secp256k1";
    let mut buf = Vec::with_capacity(
        label
            .len()
            .saturating_add(curve.len())
            .saturating_add(33 * 2)
            .saturating_add(context.len()),
    );
    buf.extend_from_slice(label);
    buf.extend_from_slice(curve);
    buf.extend_from_slice(public_key);
    buf.extend_from_slice(r_bytes);
    buf.extend_from_slice(context);

    // ~100 bytes — well below the 1 GiB SHA-256 DoS cap.
    let hash =
        sha256(&buf).map_err(|e| ZkpError::SerializationError(format!("SHA-256 failed: {}", e)))?;
    Ok(<Scalar as Reduce<U256>>::reduce_bytes(FieldBytes::from_slice(&hash)))
}

/// Schnorr proof structure
///
/// # Security
///
/// The response scalar is derived from the prover's secret key. Although proofs
/// are shared with verifiers, the raw bytes are redacted in `Debug` output to
/// prevent accidental logging of proof material that could be correlated with
/// the prover's secret.
///
/// # Cloning
///
/// `SchnorrProof` deliberately does NOT implement `Clone`. Proofs contain
/// prover-derived material, and every copy extends that material's in-memory
/// lifetime. Use [`SchnorrProof::clone_for_transmission`] when duplication
/// is genuinely needed — each call is a deliberate, grep-able audit
/// checkpoint.
#[derive(Zeroize, ZeroizeOnDrop)]
#[cfg_attr(feature = "zkp-serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "zkp-serde", serde(crate = "serde"))]
pub struct SchnorrProof {
    /// Commitment point R = k*G
    /// Consumer: verify(), commitment()
    #[cfg_attr(feature = "zkp-serde", serde(with = "serde_with::As::<serde_with::Bytes>"))]
    commitment: [u8; 33],
    /// Response s = k + c*x
    /// Consumer: verify(), response()
    #[cfg_attr(feature = "zkp-serde", serde(with = "serde_with::As::<serde_with::Bytes>"))]
    response: [u8; 32],
}

impl std::fmt::Debug for SchnorrProof {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SchnorrProof")
            .field("commitment", &"[REDACTED]")
            .field("response", &"[REDACTED]")
            .finish()
    }
}

impl ConstantTimeEq for SchnorrProof {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.commitment.ct_eq(&other.commitment) & self.response.ct_eq(&other.response)
    }
}

impl SchnorrProof {
    /// Construct a proof from raw commitment and response bytes.
    ///
    /// This is intended for deserialization and testing. Callers are responsible
    /// for ensuring the bytes represent a valid proof.
    #[must_use]
    pub fn new(commitment: [u8; 33], response: [u8; 32]) -> Self {
        Self { commitment, response }
    }

    /// Make an independent copy of this proof for transmission to a verifier.
    #[must_use]
    pub fn clone_for_transmission(&self) -> Self {
        Self { commitment: self.commitment, response: self.response }
    }

    /// Return the commitment point bytes (compressed, 33 bytes).
    #[must_use]
    pub fn commitment(&self) -> &[u8; 33] {
        &self.commitment
    }

    /// Return the response scalar bytes (32 bytes).
    #[must_use]
    pub fn response(&self) -> &[u8; 32] {
        &self.response
    }
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

impl std::fmt::Debug for SchnorrProver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SchnorrProver")
            .field("secret", &"[REDACTED]")
            .field("public_key", &"[public]")
            .finish()
    }
}

impl ConstantTimeEq for SchnorrProver {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.secret.ct_eq(&other.secret) & self.public_key.ct_eq(&other.public_key)
    }
}

impl SchnorrProver {
    /// Create a new Schnorr prover with a random secret key
    ///
    /// # Errors
    /// Returns an error if key serialization fails.
    pub fn new() -> Result<(Self, [u8; 33])> {
        // The k256 source `SecretKey` zeroizes its internal scalar on
        // drop, but `secret_key.to_bytes().into()` materialises a plain
        // `[u8; 32]` whose stack slot does not zero on shadowing/move.
        // Wrap that intermediate copy in `Zeroizing<[u8; 32]>` so when
        // the inner bytes are copied into `Self` the outer slot is wiped.
        let initial_bytes = crate::primitives::rand::csprng::random_bytes(32);
        let secret_key = SecretKey::from_slice(&initial_bytes)
            .map_err(|e| ZkpError::SerializationError(format!("Invalid secret key: {e}")))?;
        let public_key = secret_key.public_key();

        let secret_bytes_zeroizing: zeroize::Zeroizing<[u8; 32]> =
            zeroize::Zeroizing::new(secret_key.to_bytes().into());
        let public_bytes: [u8; 33] = <[u8; 33]>::try_from(public_key.to_sec1_bytes().as_ref())
            .map_err(|e| {
                ZkpError::SerializationError(format!("Failed to serialize public key: {}", e))
            })?;

        let prover = Self { secret: *secret_bytes_zeroizing, public_key: public_bytes };

        Ok((prover, public_bytes))
    }

    /// Create a prover from an existing secret key
    ///
    /// # Errors
    /// Returns an error if the secret key is invalid or serialization fails.
    pub fn from_secret(secret: &[u8; 32]) -> Result<(Self, [u8; 33])> {
        let secret_key = SecretKey::from_bytes(secret.into())
            .map_err(|e| ZkpError::SerializationError(format!("Invalid secret key format: {e}")))?;
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
        // Round-26 audit fix (M6): wrap scalars k, x, s in `Zeroizing`
        // so the stack-resident copies are scrubbed when the function
        // returns. Previously `k256::Scalar` left bare on the stack
        // would persist until overwritten by a later frame; leak of
        // the nonce `k` retroactively recovers `x = (s − k) / c`
        // (direct private-key compromise), and leak of `x` is direct.
        use zeroize::Zeroizing;

        // Parse secret key
        let x: Option<Scalar> = Scalar::from_repr(*FieldBytes::from_slice(&self.secret)).into();
        let x = Zeroizing::new(x.ok_or(ZkpError::InvalidScalar)?);

        // Round-29 M6: rejection sampling for the nonce. The previous
        // `Reduce<U256>::reduce_bytes(32 bytes)` had a modular bias of
        // ~2^-128 on secp256k1 (q is close to but less than 2^256, so
        // values `[q, 2^256)` map disproportionately to `[0, 2^256-q)`).
        // The bias is currently non-exploitable but consumes the
        // safety margin against future Bleichenbacher-class lattice
        // attacks. `Scalar::from_repr` returns `None` for byte
        // representations `>= q`, giving us textbook rejection
        // sampling: each retry succeeds with probability q/2^256 ≈
        // 1 - 2^-128, so the loop terminates in expectation in 1 + ε
        // iterations and is bounded above by ~256 with overwhelming
        // probability. Also rejects k = 0 (otherwise R = O is invalid).
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

        // Compute commitment R = k*G
        let r_point = ProjectivePoint::GENERATOR * *k;
        let r_bytes: [u8; 33] = <[u8; 33]>::try_from(r_point.to_affine().to_bytes().as_slice())
            .map_err(|e| ZkpError::SerializationError(format!("Failed to serialize R: {}", e)))?;

        // Compute challenge c = H(G || P || R || context)
        let c = fiat_shamir_challenge(&self.public_key, &r_bytes, context)?;

        // Compute response s = k + c*x. `s` is non-secret (verifier
        // sees it), but the intermediate computation passes through
        // the secret-laden registers — keep s in Zeroizing so any
        // residue is scrubbed on drop.
        let s = Zeroizing::new(*k + c * *x);
        // Round-29 N2: the byte-extracted copy of `s` is also
        // Zeroized. Although `s` itself reveals nothing about `x`
        // alone (it's a linear combination of nonce and secret),
        // careless reuse of the stack frame can leak the
        // intermediate `k + c*x` arithmetic. Treating `s_bytes` as
        // sensitive matches the discipline applied to `k` and `x`.
        let s_bytes: Zeroizing<[u8; 32]> = Zeroizing::new(s.to_bytes().into());

        Ok(SchnorrProof { commitment: r_bytes, response: *s_bytes })
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
        let r_point = Self::parse_point(proof.commitment())?;

        // Parse response s
        let s: Option<Scalar> = Scalar::from_repr(*FieldBytes::from_slice(proof.response())).into();
        let s = s.ok_or(ZkpError::InvalidScalar)?;

        // Compute challenge c = H(G || P || R || context)
        let c = fiat_shamir_challenge(&self.public_key, proof.commitment(), context)?;

        // Verify: s*G == R + c*P (constant-time comparison)
        let lhs = ProjectivePoint::GENERATOR * s;
        let rhs = r_point + p_point * c;

        Ok(bool::from(lhs.ct_eq(&rhs)))
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
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_schnorr_proof_valid_succeeds() {
        let (prover, public_key) = SchnorrProver::new().unwrap();
        let context = b"test challenge context";

        let proof = prover.prove(context).unwrap();

        let verifier = SchnorrVerifier::new(public_key);
        assert!(verifier.verify(&proof, context).unwrap());
    }

    #[test]
    fn test_schnorr_proof_wrong_context_fails() {
        let (prover, public_key) = SchnorrProver::new().unwrap();

        let proof = prover.prove(b"context 1").unwrap();

        let verifier = SchnorrVerifier::new(public_key);
        assert!(!verifier.verify(&proof, b"context 2").unwrap());
    }

    #[test]
    fn test_schnorr_proof_wrong_public_key_fails() {
        let (prover, _) = SchnorrProver::new().unwrap();
        let (_, other_public_key) = SchnorrProver::new().unwrap();

        let context = b"test";
        let proof = prover.prove(context).unwrap();

        let verifier = SchnorrVerifier::new(other_public_key);
        assert!(!verifier.verify(&proof, context).unwrap());
    }

    #[test]
    fn test_schnorr_from_secret_succeeds() {
        let secret = [42u8; 32];
        let (prover1, pk1) = SchnorrProver::from_secret(&secret).unwrap();
        let (_prover2, pk2) = SchnorrProver::from_secret(&secret).unwrap();

        assert_eq!(pk1, pk2);

        let proof = prover1.prove(b"test").unwrap();
        let verifier = SchnorrVerifier::new(pk2);
        assert!(verifier.verify(&proof, b"test").unwrap());
    }

    #[test]
    fn test_schnorr_proof_clone_for_transmission_independent_storage() {
        let proof = SchnorrProof::new([0xAA; 33], [0xBB; 32]);
        let mut cloned = proof.clone_for_transmission();
        Zeroize::zeroize(&mut cloned);
        assert_eq!(*proof.commitment(), [0xAA; 33]);
        assert_eq!(*proof.response(), [0xBB; 32]);
        assert_eq!(*cloned.commitment(), [0u8; 33]);
        assert_eq!(*cloned.response(), [0u8; 32]);
    }

    #[test]
    fn test_schnorr_proof_zeroize_wipes_all_fields() {
        let mut proof = SchnorrProof::new([0xAA; 33], [0xBB; 32]);
        Zeroize::zeroize(&mut proof);
        assert_eq!(*proof.commitment(), [0u8; 33]);
        assert_eq!(*proof.response(), [0u8; 32]);
    }
}
