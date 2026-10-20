#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

//! # Legacy RSA PKCS#1 v1.5 / SHA-1 signature verification (verify only)
//!
//! [`verify_rsa_pkcs1_sha1`] checks RSASSA-PKCS1-v1_5 signatures with SHA-1
//! (RFC 8017 §8.2.2) made by third parties, for interoperability with legacy
//! signed formats, such as signed receipts, that are still issued with
//! RSA-SHA1. It exists only to *read* such data: the crate offers no RSA
//! signing and no SHA-1 signing, and new formats should not use it.
//!
//! - The public key is given as PKCS#1 `RSAPublicKey` DER or as X.509
//!   `SubjectPublicKeyInfo` DER (algorithm `rsaEncryption`), tagged with
//!   [`RsaPublicKeyEncoding`] so that one key has one accepted encoding per
//!   call.
//! - The modulus must be 2048 to 8192 bits.
//! - Verification is done by aws-lc-rs
//!   (`RSA_PKCS1_2048_8192_SHA1_FOR_LEGACY_USE_ONLY`).
//!
//! ## FIPS
//!
//! SHA-1 is not approved for digital signatures (SP 800-131A). This module is
//! outside the FIPS-approved set and is compiled out of `--features fips`
//! builds; see `docs/FIPS_SECURITY_POLICY.md`.

use aws_lc_rs::signature::{
    RSA_PKCS1_2048_8192_SHA1_FOR_LEGACY_USE_ONLY, RsaParameters, UnparsedPublicKey,
};
use thiserror::Error;

use crate::primitives::resource_limits::validate_signature_size;

/// Smallest accepted RSA modulus, in bits.
pub const RSA_LEGACY_MIN_MODULUS_BITS: u32 = 2048;

/// Largest accepted RSA modulus, in bits.
pub const RSA_LEGACY_MAX_MODULUS_BITS: u32 = 8192;

/// Largest public key DER accepted before parsing, in bytes. An 8192-bit key
/// encodes to about 1.1 KB as `SubjectPublicKeyInfo`; the cap is roughly twice
/// that, so it never rejects a key in range but bounds the parser's input.
pub const RSA_LEGACY_MAX_PUBLIC_KEY_DER_LEN: usize = 2048;

/// DER encoding of the `rsaEncryption` `AlgorithmIdentifier`
/// (`SEQUENCE { OID 1.2.840.113549.1.1.1, NULL }`, RFC 3279 §2.3.1).
const RSA_ENCRYPTION_ALGORITHM_ID: [u8; 15] =
    [0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00];

const TAG_INTEGER: u8 = 0x02;
const TAG_BIT_STRING: u8 = 0x03;
const TAG_SEQUENCE: u8 = 0x30;

/// How the RSA public key passed to [`verify_rsa_pkcs1_sha1`] is encoded.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RsaPublicKeyEncoding<'a> {
    /// PKCS#1 `RSAPublicKey` DER: `SEQUENCE { modulus INTEGER,
    /// publicExponent INTEGER }` (RFC 8017 Appendix A.1.1).
    Pkcs1Der(&'a [u8]),
    /// X.509 `SubjectPublicKeyInfo` DER whose algorithm is `rsaEncryption`
    /// with NULL parameters (RFC 5280 §4.1, RFC 3279 §2.3.1).
    SpkiDer(&'a [u8]),
}

/// Errors from legacy RSA signature verification.
///
/// A signature that does not verify is not an error; it is `Ok(false)`.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RsaLegacyError {
    /// The public key is not well-formed DER of the declared encoding.
    #[error("invalid RSA public key encoding")]
    InvalidPublicKey,

    /// The modulus is outside the accepted 2048 to 8192 bit range.
    #[error("unsupported RSA modulus size: {bits} bits (accepted: 2048 to 8192)")]
    UnsupportedKeySize {
        /// Modulus size of the supplied key, in bits.
        bits: u32,
    },

    /// The signature length is not the modulus length.
    #[error("invalid RSA signature length: expected {expected}, got {actual}")]
    InvalidSignatureLength {
        /// Modulus length in bytes.
        expected: usize,
        /// Length of the supplied signature.
        actual: usize,
    },

    /// The message exceeds the signature resource limit.
    #[error("message exceeds signature resource limit")]
    MessageTooLong,
}

/// Split one DER TLV off the front of `input`. Only definite lengths of up to
/// two length octets in minimal form are accepted, which covers every
/// structure this module reads.
fn take_tlv(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = input.split_first()?;
    let (&first, rest) = rest.split_first()?;
    let (len, rest) = match first {
        0x00..=0x7f => (usize::from(first), rest),
        0x81 => {
            let (&b, rest) = rest.split_first()?;
            if b < 0x80 {
                return None;
            }
            (usize::from(b), rest)
        }
        0x82 => {
            let (hi, rest) = rest.split_first()?;
            let (lo, rest) = rest.split_first()?;
            let len = (usize::from(*hi) << 8) | usize::from(*lo);
            if len < 0x100 {
                return None;
            }
            (len, rest)
        }
        _ => return None,
    };
    if rest.len() < len {
        return None;
    }
    let (content, rest) = rest.split_at(len);
    Some((tag, content, rest))
}

/// Check that `der` is exactly one `SEQUENCE` whose first element is an
/// `INTEGER`, which is the outer shape of a PKCS#1 `RSAPublicKey` and not of a
/// `SubjectPublicKeyInfo`. Field contents are validated by aws-lc-rs.
fn check_pkcs1_shape(der: &[u8]) -> Option<()> {
    let (tag, content, rest) = take_tlv(der)?;
    if tag != TAG_SEQUENCE || !rest.is_empty() || content.first() != Some(&TAG_INTEGER) {
        return None;
    }
    Some(())
}

/// Unwrap a `SubjectPublicKeyInfo` for `rsaEncryption` and return the
/// `RSAPublicKey` DER it carries.
fn unwrap_spki(der: &[u8]) -> Option<&[u8]> {
    let (tag, spki, rest) = take_tlv(der)?;
    if tag != TAG_SEQUENCE || !rest.is_empty() {
        return None;
    }
    let after_alg = spki.strip_prefix(RSA_ENCRYPTION_ALGORITHM_ID.as_slice())?;
    let (tag, bits, rest) = take_tlv(after_alg)?;
    if tag != TAG_BIT_STRING || !rest.is_empty() {
        return None;
    }
    // The first BIT STRING octet counts unused bits; a DER-encoded key has none.
    bits.strip_prefix(&[0x00])
}

fn pkcs1_from_encoding(public_key: RsaPublicKeyEncoding<'_>) -> Result<&[u8], RsaLegacyError> {
    let (der, label) = match public_key {
        RsaPublicKeyEncoding::Pkcs1Der(der) => (der, "PKCS#1"),
        RsaPublicKeyEncoding::SpkiDer(der) => (der, "SPKI"),
    };
    if der.len() > RSA_LEGACY_MAX_PUBLIC_KEY_DER_LEN {
        tracing::debug!(key_len = der.len(), "RSA-SHA1 verify rejected: public key DER too long");
        return Err(RsaLegacyError::InvalidPublicKey);
    }
    let pkcs1 = match public_key {
        RsaPublicKeyEncoding::Pkcs1Der(der) => Some(der),
        RsaPublicKeyEncoding::SpkiDer(der) => unwrap_spki(der),
    }
    .filter(|inner| check_pkcs1_shape(inner).is_some());
    pkcs1.ok_or_else(|| {
        tracing::debug!(encoding = label, "RSA-SHA1 verify rejected: public key structure");
        RsaLegacyError::InvalidPublicKey
    })
}

/// Verify an RSASSA-PKCS1-v1_5 signature with SHA-1 over `message`.
///
/// Legacy, verify-only: use it to check third-party data that is still signed
/// with RSA-SHA1. The public key's modulus must be 2048 to 8192 bits and
/// `signature` must be exactly as long as the modulus.
///
/// # Errors
///
/// Returns [`RsaLegacyError::InvalidPublicKey`] if the key is not well-formed
/// DER of the declared [`RsaPublicKeyEncoding`],
/// [`RsaLegacyError::UnsupportedKeySize`] if its modulus is outside 2048 to
/// 8192 bits, [`RsaLegacyError::InvalidSignatureLength`] if `signature` is not
/// the modulus length, and [`RsaLegacyError::MessageTooLong`] if `message`
/// exceeds the signature resource limit. A signature that does not verify is
/// `Ok(false)`.
#[must_use = "the verification result must be checked"]
pub fn verify_rsa_pkcs1_sha1(
    public_key: RsaPublicKeyEncoding<'_>,
    message: &[u8],
    signature: &[u8],
) -> Result<bool, RsaLegacyError> {
    let pkcs1 = pkcs1_from_encoding(public_key)?;

    let bits = RsaParameters::public_modulus_len(pkcs1).map_err(|_e| {
        tracing::debug!("RSA-SHA1 verify rejected: RSAPublicKey did not parse");
        RsaLegacyError::InvalidPublicKey
    })?;
    if !(RSA_LEGACY_MIN_MODULUS_BITS..=RSA_LEGACY_MAX_MODULUS_BITS).contains(&bits) {
        tracing::debug!(bits, "RSA-SHA1 verify rejected: modulus size");
        return Err(RsaLegacyError::UnsupportedKeySize { bits });
    }

    let modulus_len =
        usize::try_from(bits.div_ceil(8)).map_err(|_e| RsaLegacyError::InvalidPublicKey)?;
    if signature.len() != modulus_len {
        tracing::debug!(
            sig_len = signature.len(),
            modulus_len,
            "RSA-SHA1 verify rejected: signature length"
        );
        return Err(RsaLegacyError::InvalidSignatureLength {
            expected: modulus_len,
            actual: signature.len(),
        });
    }

    if let Err(e) = validate_signature_size(message.len()) {
        tracing::debug!(error = %e, msg_len = message.len(), "RSA-SHA1 verify rejected: message exceeds resource limit");
        return Err(RsaLegacyError::MessageTooLong);
    }

    let verified = UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA1_FOR_LEGACY_USE_ONLY, pkcs1)
        .verify(message, signature)
        .is_ok();
    if !verified {
        tracing::debug!("RSA-SHA1 signature did not verify");
    }
    Ok(verified)
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects, reason = "test-only length arithmetic on small constants")]
#[expect(clippy::unwrap_used, reason = "tests use unwrap on statically valid inputs")]
#[expect(clippy::indexing_slicing, reason = "tests index into fixed-size buffers")]
mod tests {
    use super::*;
    use aws_lc_rs::encoding::AsDer;
    use aws_lc_rs::rand::SystemRandom;
    use aws_lc_rs::rsa::{KeyPair, KeySize};
    use aws_lc_rs::signature::{KeyPair as _, RSA_PKCS1_SHA256};

    fn der_len(len: usize) -> Vec<u8> {
        if len < 0x80 {
            vec![u8::try_from(len).unwrap()]
        } else if len < 0x100 {
            vec![0x81, u8::try_from(len).unwrap()]
        } else {
            vec![0x82, u8::try_from(len >> 8).unwrap(), u8::try_from(len & 0xff).unwrap()]
        }
    }

    fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut v = vec![tag];
        v.extend(der_len(content.len()));
        v.extend_from_slice(content);
        v
    }

    fn integer(be: &[u8]) -> Vec<u8> {
        let mut c = Vec::new();
        if be[0] & 0x80 != 0 {
            c.push(0);
        }
        c.extend_from_slice(be);
        tlv(TAG_INTEGER, &c)
    }

    /// PKCS#1 `RSAPublicKey` with an odd modulus of exactly `bits` bits.
    fn synthetic_pkcs1(bits: usize) -> Vec<u8> {
        let mut n = vec![0xffu8; bits / 8];
        n[0] = 0xc0;
        let mut body = integer(&n);
        body.extend(integer(&[0x01, 0x00, 0x01]));
        tlv(TAG_SEQUENCE, &body)
    }

    fn generated() -> KeyPair {
        KeyPair::generate(KeySize::Rsa2048).unwrap()
    }

    #[test]
    fn spki_unwraps_to_the_pkcs1_key() {
        let kp = generated();
        let pkcs1 = kp.public_key().as_ref().to_vec();
        let spki = kp.public_key().as_der().unwrap();
        assert_eq!(unwrap_spki(spki.as_ref()), Some(pkcs1.as_slice()));
    }

    #[test]
    fn non_sha1_signature_is_false_for_both_encodings() {
        let kp = generated();
        let msg = b"legacy receipt";
        let mut sig = vec![0u8; kp.public_modulus_len()];
        kp.sign(&RSA_PKCS1_SHA256, &SystemRandom::new(), msg, &mut sig).unwrap();
        let pkcs1 = kp.public_key().as_ref().to_vec();
        let spki = kp.public_key().as_der().unwrap();
        assert_eq!(
            verify_rsa_pkcs1_sha1(RsaPublicKeyEncoding::Pkcs1Der(&pkcs1), msg, &sig),
            Ok(false)
        );
        assert_eq!(
            verify_rsa_pkcs1_sha1(RsaPublicKeyEncoding::SpkiDer(spki.as_ref()), msg, &sig),
            Ok(false)
        );
    }

    #[test]
    fn declared_encoding_must_match() {
        let kp = generated();
        let pkcs1 = kp.public_key().as_ref().to_vec();
        let spki = kp.public_key().as_der().unwrap();
        let sig = vec![0u8; 256];
        assert_eq!(
            verify_rsa_pkcs1_sha1(RsaPublicKeyEncoding::Pkcs1Der(spki.as_ref()), b"m", &sig),
            Err(RsaLegacyError::InvalidPublicKey)
        );
        assert_eq!(
            verify_rsa_pkcs1_sha1(RsaPublicKeyEncoding::SpkiDer(&pkcs1), b"m", &sig),
            Err(RsaLegacyError::InvalidPublicKey)
        );
    }

    #[test]
    fn malformed_keys_are_errors() {
        let sig = vec![0u8; 256];
        for der in [&[][..], &[0x30][..], &[0x30, 0x00][..], &[0x02, 0x01, 0x01][..]] {
            assert_eq!(
                verify_rsa_pkcs1_sha1(RsaPublicKeyEncoding::Pkcs1Der(der), b"m", &sig),
                Err(RsaLegacyError::InvalidPublicKey)
            );
            assert_eq!(
                verify_rsa_pkcs1_sha1(RsaPublicKeyEncoding::SpkiDer(der), b"m", &sig),
                Err(RsaLegacyError::InvalidPublicKey)
            );
        }
        // Trailing bytes after the key.
        let mut trailing = generated().public_key().as_ref().to_vec();
        trailing.push(0);
        assert_eq!(
            verify_rsa_pkcs1_sha1(RsaPublicKeyEncoding::Pkcs1Der(&trailing), b"m", &sig),
            Err(RsaLegacyError::InvalidPublicKey)
        );
        // Oversized input is refused before parsing.
        let huge = vec![0x30; RSA_LEGACY_MAX_PUBLIC_KEY_DER_LEN + 1];
        assert_eq!(
            verify_rsa_pkcs1_sha1(RsaPublicKeyEncoding::Pkcs1Der(&huge), b"m", &sig),
            Err(RsaLegacyError::InvalidPublicKey)
        );
    }

    #[test]
    fn spki_with_other_algorithm_is_rejected() {
        let kp = generated();
        let mut spki = kp.public_key().as_der().unwrap().as_ref().to_vec();
        // Flip the last OID arc (rsaEncryption .1 -> .5, sha1WithRSAEncryption).
        let pos = spki.windows(9).position(|w| w == &RSA_ENCRYPTION_ALGORITHM_ID[4..13]).unwrap();
        spki[pos + 8] = 0x05;
        assert_eq!(
            verify_rsa_pkcs1_sha1(RsaPublicKeyEncoding::SpkiDer(&spki), b"m", &[0u8; 256]),
            Err(RsaLegacyError::InvalidPublicKey)
        );
    }

    #[test]
    fn modulus_size_bounds() {
        for bits in [1024usize, 2040] {
            let der = synthetic_pkcs1(bits);
            assert_eq!(
                verify_rsa_pkcs1_sha1(RsaPublicKeyEncoding::Pkcs1Der(&der), b"m", &[0u8; 256]),
                Err(RsaLegacyError::UnsupportedKeySize { bits: u32::try_from(bits).unwrap() })
            );
        }
        let der = synthetic_pkcs1(8200);
        assert_eq!(
            verify_rsa_pkcs1_sha1(RsaPublicKeyEncoding::Pkcs1Der(&der), b"m", &[0u8; 1025]),
            Err(RsaLegacyError::UnsupportedKeySize { bits: 8200 })
        );
        // In range: the shape checks pass and the bad signature is Ok(false).
        let der = synthetic_pkcs1(2048);
        assert_eq!(
            verify_rsa_pkcs1_sha1(RsaPublicKeyEncoding::Pkcs1Der(&der), b"m", &[1u8; 256]),
            Ok(false)
        );
    }

    #[test]
    fn signature_must_be_modulus_length() {
        let kp = generated();
        let pkcs1 = kp.public_key().as_ref().to_vec();
        for len in [0usize, 255, 257, 512] {
            assert_eq!(
                verify_rsa_pkcs1_sha1(
                    RsaPublicKeyEncoding::Pkcs1Der(&pkcs1),
                    b"m",
                    &vec![0u8; len]
                ),
                Err(RsaLegacyError::InvalidSignatureLength { expected: 256, actual: len })
            );
        }
    }

    #[test]
    fn oversized_message_is_rejected() {
        let kp = generated();
        let pkcs1 = kp.public_key().as_ref().to_vec();
        let limit = crate::primitives::resource_limits::get_global_resource_limits()
            .get_limits()
            .unwrap()
            .max_signature_size_bytes;
        assert_eq!(
            verify_rsa_pkcs1_sha1(
                RsaPublicKeyEncoding::Pkcs1Der(&pkcs1),
                &vec![0u8; limit + 1],
                &[0u8; 256]
            ),
            Err(RsaLegacyError::MessageTooLong)
        );
    }

    #[test]
    fn der_reader_rejects_non_minimal_lengths() {
        assert!(take_tlv(&[0x04, 0x81, 0x05, 1, 2, 3, 4, 5]).is_none());
        assert!(take_tlv(&[0x04, 0x82, 0x00, 0x05, 1, 2, 3, 4, 5]).is_none());
        assert!(take_tlv(&[0x04, 0x80]).is_none());
        assert!(take_tlv(&[0x04, 0x03, 1, 2]).is_none());
        assert_eq!(take_tlv(&[0x04, 0x02, 1, 2, 9]), Some((0x04, &[1u8, 2][..], &[9u8][..])));
    }
}
