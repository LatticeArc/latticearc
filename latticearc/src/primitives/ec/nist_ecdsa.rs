#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

//! Shared ECDSA verification core for the NIST prime curves.
//!
//! [`super::p256`] and [`super::p384`] are thin per-curve front ends over the
//! single implementation here, which routes every verification through
//! aws-lc-rs (`signature::ParsedPublicKey`). Keeping one code path means the
//! input checks (key encoding, signature length bounds, message resource
//! limit) and the result convention are identical for both curves.
//!
//! Result convention, shared by every public function built on this module:
//!
//! - `Err` for inputs that are wrong *before* any signature arithmetic runs:
//!   a public key that is not uncompressed SEC1 of the expected length or is
//!   not a point on the curve, a signature whose length is impossible for the
//!   encoding, or a message above the signature resource limit.
//! - `Ok(false)` for a well-formed request whose signature does not verify,
//!   including a DER signature whose contents do not parse.
//! - `Ok(true)` only for a valid signature.

use aws_lc_rs::digest;
use aws_lc_rs::signature::{EcdsaVerificationAlgorithm, ParsedPublicKey};

use crate::prelude::error::{LatticeArcError, Result};
use crate::primitives::resource_limits::validate_signature_size;

/// SEC1 tag byte for an uncompressed point (`0x04 || X || Y`).
const SEC1_UNCOMPRESSED_TAG: u8 = 0x04;

/// Per-curve parameters for the shared verifier.
pub(super) struct CurveParams {
    /// Curve name used in debug events and error strings.
    pub(super) name: &'static str,
    /// Uncompressed SEC1 public key length (`1 + 2 * field_len`).
    pub(super) public_key_len: usize,
    /// Fixed-width `r || s` signature length (`2 * scalar_len`).
    pub(super) fixed_signature_len: usize,
    /// Upper bound on a DER `SEQUENCE { INTEGER r, INTEGER s }` encoding.
    pub(super) max_der_signature_len: usize,
    /// aws-lc-rs algorithm for ASN.1 DER signatures.
    pub(super) asn1: &'static EcdsaVerificationAlgorithm,
    /// aws-lc-rs algorithm for fixed-width `r || s` signatures.
    pub(super) fixed: &'static EcdsaVerificationAlgorithm,
    /// Digest algorithm the curve is paired with.
    pub(super) digest: &'static digest::Algorithm,
}

/// Signature encoding accepted by a verification call.
#[derive(Clone, Copy)]
pub(super) enum SigEncoding {
    /// ASN.1 DER `Ecdsa-Sig-Value` (RFC 3279 §2.2.3), as used by X.509.
    Der,
    /// Fixed-width big-endian `r || s` (IEEE P1363), as used by JWS and COSE.
    Fixed,
}

/// What the signature covers.
pub(super) enum Signed<'a> {
    /// The message itself; it is hashed with the curve's digest.
    Message(&'a [u8]),
    /// A digest computed by the caller with the curve's digest algorithm.
    Digest(&'a [u8]),
}

fn parse_public_key(
    curve: &CurveParams,
    alg: &'static EcdsaVerificationAlgorithm,
    public_key_sec1: &[u8],
) -> Result<ParsedPublicKey> {
    if public_key_sec1.len() != curve.public_key_len {
        tracing::debug!(
            curve = curve.name,
            pk_len = public_key_sec1.len(),
            "ECDSA verify rejected: public key length"
        );
        return Err(LatticeArcError::InvalidKeyLength {
            expected: curve.public_key_len,
            actual: public_key_sec1.len(),
        });
    }
    // Only the uncompressed form is accepted: aws-lc-rs would otherwise also
    // take compressed points and SubjectPublicKeyInfo DER, which gives one
    // key several byte identities.
    if public_key_sec1.first() != Some(&SEC1_UNCOMPRESSED_TAG) {
        tracing::debug!(curve = curve.name, "ECDSA verify rejected: SEC1 tag is not uncompressed");
        return Err(LatticeArcError::InvalidKey(format!(
            "{} public key must be uncompressed SEC1",
            curve.name
        )));
    }
    ParsedPublicKey::new(alg, public_key_sec1).map_err(|e| {
        tracing::debug!(curve = curve.name, error = %e, "ECDSA verify rejected: point validation");
        LatticeArcError::InvalidKey(format!("invalid {} public key", curve.name))
    })
}

fn check_signature_len(curve: &CurveParams, encoding: SigEncoding, len: usize) -> Result<()> {
    let ok = match encoding {
        SigEncoding::Fixed => len == curve.fixed_signature_len,
        SigEncoding::Der => len > 0 && len <= curve.max_der_signature_len,
    };
    if ok {
        return Ok(());
    }
    tracing::debug!(curve = curve.name, sig_len = len, "ECDSA verify rejected: signature length");
    let expected = match encoding {
        SigEncoding::Fixed => curve.fixed_signature_len,
        SigEncoding::Der => curve.max_der_signature_len,
    };
    Err(LatticeArcError::InvalidSignatureLength { expected, got: len })
}

/// Verify one ECDSA signature for `curve`. See the module docs for the result
/// convention.
pub(super) fn verify(
    curve: &CurveParams,
    encoding: SigEncoding,
    public_key_sec1: &[u8],
    signed: &Signed<'_>,
    signature: &[u8],
) -> Result<bool> {
    let alg = match encoding {
        SigEncoding::Der => curve.asn1,
        SigEncoding::Fixed => curve.fixed,
    };
    let key = parse_public_key(curve, alg, public_key_sec1)?;
    check_signature_len(curve, encoding, signature.len())?;

    let verified = match signed {
        Signed::Message(message) => {
            if let Err(e) = validate_signature_size(message.len()) {
                tracing::debug!(
                    curve = curve.name,
                    error = %e,
                    msg_len = message.len(),
                    "ECDSA verify rejected: message exceeds resource limit"
                );
                return Err(LatticeArcError::MessageTooLong);
            }
            key.verify_sig(message, signature).is_ok()
        }
        Signed::Digest(bytes) => {
            let digest = digest::Digest::import_less_safe(bytes, curve.digest).map_err(|_e| {
                // Unreachable through the public API (callers pass a
                // fixed-size array), kept as an error rather than a panic.
                LatticeArcError::InvalidInput(format!("{} digest length", curve.name))
            })?;
            key.verify_digest_sig(&digest, signature).is_ok()
        }
    };
    if !verified {
        tracing::debug!(curve = curve.name, "ECDSA signature did not verify");
    }
    Ok(verified)
}
