#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

//! # ECDSA over NIST P256 with SHA-256 (verify only)
//!
//! Verification of ECDSA P256 / SHA-256 signatures (FIPS 186-5) produced
//! by third parties, for interoperability with signed formats such as JWS
//! (`ES256`, fixed-width `r || s`), COSE, and X.509 certificate chains
//! (ASN.1 DER `Ecdsa-Sig-Value`). Backed by aws-lc-rs.
//!
//! | Function | Signature encoding | Signed input |
//! |---|---|---|
//! | [`verify_ecdsa_p256_sha256`] | ASN.1 DER | message |
//! | [`verify_ecdsa_p256_sha256_prehash`] | ASN.1 DER | SHA-256 digest |
//! | [`verify_ecdsa_p256_sha256_fixed`] | `r \|\| s` (64 bytes) | message |
//! | [`verify_ecdsa_p256_sha256_prehash_fixed`] | `r \|\| s` (64 bytes) | SHA-256 digest |
//!
//! ## Result convention
//!
//! - The public key must be the 65-byte uncompressed SEC1 encoding
//!   (`0x04 || X || Y`) of a point on the curve; any other length, the
//!   compressed form, or an off-curve point is an `Err`. The key is checked
//!   before anything else.
//! - A signature of impossible length is an `Err`: fixed-width signatures
//!   must be exactly 64 bytes, DER signatures 1 to
//!   [`P256_MAX_DER_SIGNATURE_LEN`] bytes.
//! - A message longer than the signature resource limit
//!   (`max_signature_size_bytes`, 64 KiB by default) is an `Err`.
//! - Otherwise the call returns `Ok(true)` for a valid signature and
//!   `Ok(false)` for any signature that does not verify, including a DER
//!   value that does not parse.
//!
//! ## FIPS
//!
//! ECDSA P256 / SHA-256 verification over a message is a FIPS 186-5
//! approved service of the aws-lc-rs module. The `_prehash` variants verify a
//! caller-supplied digest; aws-lc-rs does not list digest verification as an
//! approved service, so they are documented as non-approved in
//! `docs/FIPS_SECURITY_POLICY.md`.

use aws_lc_rs::digest;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1, ECDSA_P256_SHA256_FIXED};

use super::nist_ecdsa::{self, CurveParams, SigEncoding, Signed};
use crate::prelude::error::Result;

/// Length of an uncompressed SEC1 P256 public key (`0x04 || X || Y`).
pub const P256_PUBLIC_KEY_LEN: usize = 65;

/// Length of a fixed-width (`r || s`) P256 ECDSA signature.
pub const P256_FIXED_SIGNATURE_LEN: usize = 64;

/// Upper bound on the length of a DER-encoded P256 ECDSA signature
/// (`SEQUENCE { INTEGER r, INTEGER s }` with both integers at their maximum
/// encoded width).
pub const P256_MAX_DER_SIGNATURE_LEN: usize = 72;

/// Length of the SHA-256 digest accepted by the `_prehash` variants.
pub const P256_DIGEST_LEN: usize = 32;

static CURVE: CurveParams = CurveParams {
    name: "P256",
    public_key_len: P256_PUBLIC_KEY_LEN,
    fixed_signature_len: P256_FIXED_SIGNATURE_LEN,
    max_der_signature_len: P256_MAX_DER_SIGNATURE_LEN,
    asn1: &ECDSA_P256_SHA256_ASN1,
    fixed: &ECDSA_P256_SHA256_FIXED,
    digest: &digest::SHA256,
};

/// Verify an ASN.1 DER ECDSA P256 / SHA-256 signature over `message`.
///
/// This is the encoding X.509 certificates and CMS carry.
///
/// # Errors
///
/// Returns `InvalidKeyLength` or `InvalidKey` if `public_key_sec1` is not a
/// 65-byte uncompressed SEC1 point on the curve, `InvalidSignatureLength`
/// if `signature_der` is empty or longer than
/// [`P256_MAX_DER_SIGNATURE_LEN`], and `MessageTooLong` if `message`
/// exceeds the signature resource limit. A signature that does not verify is
/// `Ok(false)`, not an error.
#[must_use = "the verification result must be checked"]
pub fn verify_ecdsa_p256_sha256(
    public_key_sec1: &[u8],
    message: &[u8],
    signature_der: &[u8],
) -> Result<bool> {
    nist_ecdsa::verify(
        &CURVE,
        SigEncoding::Der,
        public_key_sec1,
        &Signed::Message(message),
        signature_der,
    )
}

/// Verify an ASN.1 DER ECDSA P256 signature over a SHA-256 digest that the
/// caller computed, for example the hash of an X.509 `tbsCertificate`.
///
/// The caller is responsible for `digest` really being the SHA-256 of the
/// intended message.
///
/// # Errors
///
/// Returns `InvalidKeyLength` or `InvalidKey` for a public key that is not a
/// 65-byte uncompressed SEC1 point on the curve, and
/// `InvalidSignatureLength` if `signature_der` is empty or longer than
/// [`P256_MAX_DER_SIGNATURE_LEN`]. A signature that does not verify is
/// `Ok(false)`.
#[must_use = "the verification result must be checked"]
pub fn verify_ecdsa_p256_sha256_prehash(
    public_key_sec1: &[u8],
    digest: &[u8; P256_DIGEST_LEN],
    signature_der: &[u8],
) -> Result<bool> {
    nist_ecdsa::verify(
        &CURVE,
        SigEncoding::Der,
        public_key_sec1,
        &Signed::Digest(digest),
        signature_der,
    )
}

/// Verify a fixed-width (`r || s`, 64 bytes) ECDSA P256 / SHA-256
/// signature over `message`.
///
/// This is the encoding JWS (`ES256`, RFC 7518 §3.4) and COSE carry.
///
/// # Errors
///
/// Returns `InvalidKeyLength` or `InvalidKey` for a public key that is not a
/// 65-byte uncompressed SEC1 point on the curve,
/// `InvalidSignatureLength` if `signature` is not exactly
/// [`P256_FIXED_SIGNATURE_LEN`] bytes, and `MessageTooLong` if `message`
/// exceeds the signature resource limit. A signature that does not verify is
/// `Ok(false)`.
#[must_use = "the verification result must be checked"]
pub fn verify_ecdsa_p256_sha256_fixed(
    public_key_sec1: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<bool> {
    nist_ecdsa::verify(
        &CURVE,
        SigEncoding::Fixed,
        public_key_sec1,
        &Signed::Message(message),
        signature,
    )
}

/// Verify a fixed-width (`r || s`, 64 bytes) ECDSA P256 signature over
/// a SHA-256 digest that the caller computed, for example the hash of a COSE
/// `Sig_structure`.
///
/// # Errors
///
/// Returns `InvalidKeyLength` or `InvalidKey` for a public key that is not a
/// 65-byte uncompressed SEC1 point on the curve, and
/// `InvalidSignatureLength` if `signature` is not exactly
/// [`P256_FIXED_SIGNATURE_LEN`] bytes. A signature that does not verify is
/// `Ok(false)`.
#[must_use = "the verification result must be checked"]
pub fn verify_ecdsa_p256_sha256_prehash_fixed(
    public_key_sec1: &[u8],
    digest: &[u8; P256_DIGEST_LEN],
    signature: &[u8],
) -> Result<bool> {
    nist_ecdsa::verify(
        &CURVE,
        SigEncoding::Fixed,
        public_key_sec1,
        &Signed::Digest(digest),
        signature,
    )
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects, reason = "test-only length arithmetic on small constants")]
#[expect(clippy::unwrap_used, reason = "tests use unwrap on statically valid inputs")]
#[expect(clippy::indexing_slicing, reason = "tests index into fixed-size buffers")]
mod tests {
    use super::*;
    use crate::prelude::error::LatticeArcError;
    use aws_lc_rs::rand::SystemRandom;
    use aws_lc_rs::signature::{
        ECDSA_P256_SHA256_ASN1_SIGNING, ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair,
    };
    use sha2::{Digest, Sha256};

    struct Fixture {
        public_key: Vec<u8>,
        der_key: EcdsaKeyPair,
        fixed_key: EcdsaKeyPair,
    }

    // One key, loaded under both signing encodings, so DER and fixed-width
    // signatures verify against the same SEC1 public key.
    fn fixture() -> Fixture {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        let der_key =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref()).unwrap();
        let fixed_key =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref()).unwrap();
        let public_key = der_key.public_key().as_ref().to_vec();
        Fixture { public_key, der_key, fixed_key }
    }

    fn sign_der(f: &Fixture, msg: &[u8]) -> Vec<u8> {
        f.der_key.sign(&SystemRandom::new(), msg).unwrap().as_ref().to_vec()
    }

    fn sign_fixed(f: &Fixture, msg: &[u8]) -> Vec<u8> {
        f.fixed_key.sign(&SystemRandom::new(), msg).unwrap().as_ref().to_vec()
    }

    fn digest_of(msg: &[u8]) -> [u8; P256_DIGEST_LEN] {
        Sha256::digest(msg).into()
    }

    #[test]
    fn public_key_is_uncompressed_sec1() {
        let f = fixture();
        assert_eq!(f.public_key.len(), P256_PUBLIC_KEY_LEN);
        assert_eq!(f.public_key[0], 0x04);
    }

    #[test]
    fn der_roundtrip_and_tamper() {
        let f = fixture();
        let msg = b"ecdsa p256 der message";
        let sig = sign_der(&f, msg);
        assert!(sig.len() <= P256_MAX_DER_SIGNATURE_LEN);
        assert_eq!(verify_ecdsa_p256_sha256(&f.public_key, msg, &sig).ok(), Some(true));
        assert_eq!(
            verify_ecdsa_p256_sha256(&f.public_key, b"other message", &sig).ok(),
            Some(false)
        );
        let mut bad = sig;
        let last = bad.len() - 1;
        bad[last] ^= 0x01;
        assert_eq!(verify_ecdsa_p256_sha256(&f.public_key, msg, &bad).ok(), Some(false));
    }

    #[test]
    fn fixed_roundtrip_and_tamper() {
        let f = fixture();
        let msg = b"ecdsa p256 fixed message";
        let sig = sign_fixed(&f, msg);
        assert_eq!(sig.len(), P256_FIXED_SIGNATURE_LEN);
        assert_eq!(verify_ecdsa_p256_sha256_fixed(&f.public_key, msg, &sig).ok(), Some(true));
        let mut bad = sig;
        bad[0] ^= 0x80;
        assert_eq!(verify_ecdsa_p256_sha256_fixed(&f.public_key, msg, &bad).ok(), Some(false));
        // All-zero r and s are out of range and never verify.
        assert_eq!(
            verify_ecdsa_p256_sha256_fixed(&f.public_key, msg, &[0u8; P256_FIXED_SIGNATURE_LEN])
                .ok(),
            Some(false)
        );
    }

    #[test]
    fn prehash_variants_match_message_variants() {
        let f = fixture();
        let msg = b"prehash payload";
        let digest = digest_of(msg);
        let der = sign_der(&f, msg);
        let fixed = sign_fixed(&f, msg);
        assert_eq!(verify_ecdsa_p256_sha256_prehash(&f.public_key, &digest, &der).ok(), Some(true));
        assert_eq!(
            verify_ecdsa_p256_sha256_prehash_fixed(&f.public_key, &digest, &fixed).ok(),
            Some(true)
        );
        let other = digest_of(b"other payload");
        assert_eq!(verify_ecdsa_p256_sha256_prehash(&f.public_key, &other, &der).ok(), Some(false));
        assert_eq!(
            verify_ecdsa_p256_sha256_prehash_fixed(&f.public_key, &other, &fixed).ok(),
            Some(false)
        );
    }

    #[test]
    fn encodings_are_not_interchangeable() {
        let f = fixture();
        let msg = b"encoding confusion";
        let fixed = sign_fixed(&f, msg);
        // A fixed-width value handed to the DER verifier fits the DER length
        // bound but does not parse as DER: Ok(false).
        assert_eq!(verify_ecdsa_p256_sha256(&f.public_key, msg, &fixed).ok(), Some(false));
        // A DER value handed to the fixed verifier has the wrong length: Err.
        let der = sign_der(&f, msg);
        if der.len() != P256_FIXED_SIGNATURE_LEN {
            assert!(matches!(
                verify_ecdsa_p256_sha256_fixed(&f.public_key, msg, &der),
                Err(LatticeArcError::InvalidSignatureLength { .. })
            ));
        }
    }

    #[test]
    fn public_key_checks_come_first() {
        let f = fixture();
        let msg = b"m";
        let sig = sign_der(&f, msg);
        // Wrong length.
        assert!(matches!(
            verify_ecdsa_p256_sha256(&f.public_key[..10], msg, &sig),
            Err(LatticeArcError::InvalidKeyLength { expected: P256_PUBLIC_KEY_LEN, actual: 10 })
        ));
        // Wrong SEC1 tag at the right length.
        let mut tagged = f.public_key.clone();
        tagged[0] = 0x06;
        assert!(matches!(
            verify_ecdsa_p256_sha256(&tagged, msg, &sig),
            Err(LatticeArcError::InvalidKey(_))
        ));
        // Off-curve point.
        let mut off_curve = f.public_key.clone();
        off_curve[65 - 1] ^= 0x01;
        assert!(matches!(
            verify_ecdsa_p256_sha256(&off_curve, msg, &sig),
            Err(LatticeArcError::InvalidKey(_))
        ));
        // A key error wins over a signature length error.
        assert!(matches!(
            verify_ecdsa_p256_sha256_fixed(&off_curve, msg, &[]),
            Err(LatticeArcError::InvalidKey(_))
        ));
        // Compressed form of a valid key is refused.
        let mut compressed = vec![0x02 | (f.public_key[65 - 1] & 1)];
        compressed.extend_from_slice(&f.public_key[1..1 + (65 - 1) / 2]);
        assert!(matches!(
            verify_ecdsa_p256_sha256(&compressed, msg, &sig),
            Err(LatticeArcError::InvalidKeyLength { .. })
        ));
    }

    #[test]
    fn signature_length_bounds() {
        let f = fixture();
        let msg = b"m";
        assert!(matches!(
            verify_ecdsa_p256_sha256(&f.public_key, msg, &[]),
            Err(LatticeArcError::InvalidSignatureLength { .. })
        ));
        assert!(matches!(
            verify_ecdsa_p256_sha256(&f.public_key, msg, &[0u8; P256_MAX_DER_SIGNATURE_LEN + 1]),
            Err(LatticeArcError::InvalidSignatureLength { .. })
        ));
        assert!(matches!(
            verify_ecdsa_p256_sha256_fixed(
                &f.public_key,
                msg,
                &[0u8; P256_FIXED_SIGNATURE_LEN - 1]
            ),
            Err(LatticeArcError::InvalidSignatureLength { .. })
        ));
    }

    #[test]
    fn oversized_message_is_rejected() {
        let f = fixture();
        let limit = crate::primitives::resource_limits::get_global_resource_limits()
            .get_limits()
            .unwrap()
            .max_signature_size_bytes;
        let big = vec![0u8; limit + 1];
        let sig = sign_fixed(&f, b"m");
        assert!(matches!(
            verify_ecdsa_p256_sha256_fixed(&f.public_key, &big, &sig),
            Err(LatticeArcError::MessageTooLong)
        ));
    }
}
