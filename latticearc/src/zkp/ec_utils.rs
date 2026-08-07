//! Shared secp256k1 helpers for the ZKP module's Schnorr and sigma-protocol
//! implementations.
//!
//! `schnorr.rs` and `sigma.rs` each independently implemented the same three
//! low-level operations: nonce sampling, Fiat-Shamir rejection-sampling
//! challenge derivation, and SEC1 point parsing with identity rejection.
//! Centralizing them here means the underlying security invariants —
//! rejection sampling instead of modular reduction, zero-rejection,
//! identity-rejection — are implemented and documented exactly once instead
//! of drifting between two copies.
//!
//! Module-private (`pub(super)`): these are implementation details of the
//! ZKP primitives, not part of the crate's public API.

use crate::primitives::hash::sha2::sha256;
use crate::zkp::error::{Result, ZkpError};
use k256::{
    EncodedPoint, FieldBytes, ProjectivePoint, Scalar,
    elliptic_curve::{Group, PrimeField, sec1::FromEncodedPoint},
};
use subtle::ConstantTimeEq;

/// Sample a uniformly random, nonzero secp256k1 scalar from the OS CSPRNG.
///
/// Used both as the Schnorr proof nonce `k` and as the sigma-protocol
/// commitment randomness — both callers wrap the result in
/// `zeroize::Zeroizing` themselves.
///
/// # Why rejection sampling instead of reduction
/// `Scalar::from_repr` returns `None` for the ~2^-128 fraction of 32-byte
/// strings that fall in `[q, 2^256)`, where `q` is the secp256k1 scalar
/// field order. Reducing those bytes modulo `q` (e.g. via
/// `Reduce::reduce_bytes`) would map them disproportionately onto
/// `[0, 2^256 - q)`, introducing measurable modular bias. Retrying on
/// `None` instead keeps every *accepted* scalar uniform over `[0, q)`.
/// Expected iterations: 1 + ε; the loop terminates within ~256 iterations
/// with overwhelming probability.
///
/// # Why reject zero
/// A zero nonce degenerates the response to `s = k + c·x = c·x` (an
/// immediate leak of the `c·x` term) and collapses the commitment point to
/// the identity (`R = 0·G`), destroying the proof's hiding property.
/// Rejecting `k = 0` costs nothing (probability ~2^-256) and removes the
/// degenerate case entirely.
///
/// Each rejected candidate's raw bytes live in `zeroize::Zeroizing` so they
/// are scrubbed before the next iteration allocates a new candidate.
pub(super) fn sample_nonzero_scalar() -> Scalar {
    loop {
        let nonce_bytes =
            zeroize::Zeroizing::new(crate::primitives::rand::csprng::random_bytes(32));
        let candidate: Option<Scalar> =
            Scalar::from_repr(*FieldBytes::from_slice(&nonce_bytes)).into();
        if let Some(s) = candidate
            && !bool::from(s.ct_eq(&Scalar::ZERO))
        {
            return s;
        }
    }
}

/// Parse a SEC1 compressed secp256k1 point, rejecting the identity.
///
/// secp256k1 has cofactor 1, so small-subgroup attacks aren't a concern
/// here, but the identity point is still algebraically dangerous: any
/// verification equation of the shape `s·G == R + c·P` (Schnorr) or
/// `s·G == A + c·P` (sigma protocols) collapses to a `c`-independent check
/// when `P` is the identity, letting a forger satisfy it without knowledge
/// of any discrete log. Rejecting identity here, at the single parse
/// choke point both verifiers go through, keeps that invariant enforced
/// in one place instead of re-checked (or missed) at each call site.
///
/// # Errors
/// Returns [`ZkpError::SerializationError`] if `bytes` is not a valid SEC1
/// encoding, or [`ZkpError::InvalidPublicKey`] if the bytes decode to a
/// point that is not on the curve, or is the identity.
pub(super) fn parse_compressed_point(bytes: &[u8; 33]) -> Result<ProjectivePoint> {
    let encoded = EncodedPoint::from_bytes(bytes)
        .map_err(|e| ZkpError::SerializationError(format!("Invalid point encoding: {e}")))?;
    let point: Option<ProjectivePoint> = ProjectivePoint::from_encoded_point(&encoded).into();
    let p = point.ok_or(ZkpError::InvalidPublicKey)?;
    if bool::from(p.is_identity()) {
        return Err(ZkpError::InvalidPublicKey);
    }
    Ok(p)
}

/// Shared Fiat-Shamir rejection-sampling challenge loop.
///
/// Repeatedly asks `build_transcript` to fill a fresh, empty buffer for
/// the current `counter` (starting at 0), hashes the buffer with
/// SHA-256, and returns the digest the first time it parses as a
/// **nonzero** scalar strictly less than the secp256k1 group order `q`.
/// On rejection, `counter` is incremented and the transcript is rebuilt
/// from scratch via another call to `build_transcript`.
///
/// This function owns only the "assemble, hash, check, retry" loop and
/// the rejection predicate — it has no opinion on domain label, field
/// order, or how the counter is encoded into the transcript. Callers
/// own the transcript layout entirely, so two callers with structurally
/// different transcripts (e.g. `schnorr`'s `label ‖ curve ‖ pk ‖ R ‖ ctx
/// ‖ counter_be` vs. sigma's `label ‖ g ‖ h ‖ p ‖ q ‖ a ‖ b ‖ ctx ‖
/// counter_be`) still get byte-identical challenges to what a
/// hand-rolled loop would have produced, while sharing the
/// rejection-sampling logic and its safety invariants. Both existing
/// callers encode `counter` as 4-byte big-endian, but that choice lives
/// entirely in their closures, not here.
///
/// # Why rejection sampling instead of reduction
/// See [`sample_nonzero_scalar`] — the same modular-bias argument
/// applies to challenge derivation: a plain `Reduce::reduce_bytes` would
/// bias the challenge distribution by ~2^-128, unnecessary sloppiness in
/// a soundness-critical value.
///
/// # Why reject zero
/// If the challenge `c` were zero, the response would collapse to
/// `s = k + 0·x = k`, directly exposing the prover's nonce. Probability
/// ~2^-256 — defense-in-depth, not an exploitable attack — but symmetric
/// with the nonce-side zero rejection in [`sample_nonzero_scalar`].
///
/// # Errors
/// Returns an error if the SHA-256 primitive fails (input exceeds the
/// 1 GiB guard), or — astronomically rarely — if the counter overflows
/// `u32::MAX` without finding a hash output `< q`.
pub(super) fn derive_challenge_bytes<F>(mut build_transcript: F) -> Result<[u8; 32]>
where
    F: FnMut(u32, &mut Vec<u8>),
{
    let mut counter: u32 = 0;
    loop {
        let mut buf = Vec::new();
        build_transcript(counter, &mut buf);

        let hash = sha256(&buf)
            .map_err(|e| ZkpError::SerializationError(format!("SHA-256 failed: {e}")))?;
        let cand: Option<Scalar> = Scalar::from_repr(*FieldBytes::from_slice(&hash)).into();
        if let Some(s) = cand
            && !bool::from(s.ct_eq(&Scalar::ZERO))
        {
            return Ok(hash);
        }
        counter = counter.checked_add(1).ok_or_else(|| {
            ZkpError::SerializationError(
                "Fiat-Shamir challenge derivation: counter overflow (statistically impossible)"
                    .to_string(),
            )
        })?;
    }
}
