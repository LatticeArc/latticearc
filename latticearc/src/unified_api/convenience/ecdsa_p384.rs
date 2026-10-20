//! ECDSA over NIST P-384 (FIPS 186-4) convenience facade.
//!
//! Sign/verify with ECDSA-P384/SHA-384, plus a prehash verify for protocols that
//! sign over an already-computed digest (e.g. COSE_Sign1 in AWS Nitro Enclave
//! attestation). Mirrors the [`super::ed25519`] facade: `SecurityMode`-gated,
//! returns the crate `Result`, and never panics.
//!
//! Signing uses the RustCrypto `p384` crate. Every verify function delegates
//! to [`crate::primitives::ec::p384`] (aws-lc-rs), so there is a single P-384
//! verification implementation in the crate; this facade only adds the
//! session check, accepts any SEC1 public key form, and keeps its historical
//! convention that a signature of the wrong length is `Ok(false)`.

use p384::ecdsa::{Signature, SigningKey, VerifyingKey, signature::Signer};
use p384::elliptic_curve::Generate;
use zeroize::Zeroizing;

use crate::prelude::error::LatticeArcError;
use crate::primitives::ec::p384 as p384_verify;
use crate::primitives::resource_limits::validate_signature_size;
use crate::unified_api::error::{CoreError, Result};
use crate::unified_api::zero_trust::SecurityMode;

/// Fixed-size (r‖s) P-384 signature length, in bytes.
pub const ECDSA_P384_SIGNATURE_LEN: usize = 96;

/// Parse any SEC1 form (compressed or uncompressed) and return the
/// uncompressed encoding the primitive verifier requires.
fn uncompressed_public_key(public_key: &[u8]) -> Result<Vec<u8>> {
    let vk = VerifyingKey::from_sec1_bytes(public_key).map_err(|_e| {
        CoreError::InvalidKey("invalid P-384 public key (expected SEC1)".to_string())
    })?;
    Ok(vk.to_sec1_point(false).as_bytes().to_vec())
}

fn sha384_prehash(prehash: &[u8]) -> Result<&[u8; p384_verify::P384_DIGEST_LEN]> {
    prehash.try_into().map_err(|_e| {
        CoreError::InvalidInput(format!(
            "P-384 prehash must be a {}-byte SHA-384 digest",
            p384_verify::P384_DIGEST_LEN
        ))
    })
}

/// Map the primitive's result onto this facade's convention.
fn facade_result(result: crate::prelude::error::Result<bool>) -> Result<bool> {
    match result {
        Ok(verified) => Ok(verified),
        Err(LatticeArcError::InvalidSignatureLength { .. }) => Ok(false),
        Err(LatticeArcError::MessageTooLong) => {
            Err(CoreError::ResourceExceeded("message exceeds resource limit".to_string()))
        }
        Err(e) => Err(CoreError::from(e)),
    }
}

/// Generate a P-384 keypair: `(public_key_sec1_uncompressed, secret_key_scalar)`.
/// The returned secret key is zeroized on drop.
///
/// # Errors
/// Returns an error if the session is invalid under `SecurityMode::Verified`.
pub fn generate_ecdsa_p384_keypair(mode: SecurityMode) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>)> {
    // FIPS 140-3 §9.6: no cryptographic service while the module is in an
    // error state. This module reaches `primitives::*` directly rather than
    // routing through `unified_api::{encrypt,decrypt,sign,verify}`, so the
    // latch has to be consulted here or a consumer of this module alone
    // would never see it.
    super::api::fips_verify_operational()?;
    mode.validate()?;
    let sk = SigningKey::generate_from_rng(&mut crate::primitives::rand::secure_rng());
    let public_key = VerifyingKey::from(&sk).to_sec1_point(false).as_bytes().to_vec();
    let secret_key = Zeroizing::new(sk.to_bytes().to_vec());
    Ok((public_key, secret_key))
}

/// Sign `data` with ECDSA-P384/SHA-384, producing a fixed-size (r‖s) signature.
///
/// # Errors
/// Returns an error on an invalid secret key, an oversized message, or an invalid
/// session.
pub fn sign_ecdsa_p384(data: &[u8], secret_key: &[u8], mode: SecurityMode) -> Result<Vec<u8>> {
    super::api::fips_verify_operational()?;
    mode.validate()?;
    validate_signature_size(data.len())
        .map_err(|_e| CoreError::ResourceExceeded("message exceeds resource limit".to_string()))?;
    let sk = SigningKey::from_slice(secret_key)
        .map_err(|_e| CoreError::InvalidKey("invalid P-384 secret key".to_string()))?;
    let signature: Signature = sk.sign(data);
    Ok(signature.to_bytes().to_vec())
}

/// Verify an ECDSA-P384/SHA-384 signature over `data`. A non-matching or
/// malformed signature returns `Ok(false)`, not an error.
///
/// # Errors
/// Returns an error on an invalid public key, an oversized message, or an invalid
/// session.
pub fn verify_ecdsa_p384(
    data: &[u8],
    signature: &[u8],
    public_key: &[u8],
    mode: SecurityMode,
) -> Result<bool> {
    super::api::fips_verify_operational()?;
    mode.validate()?;
    validate_signature_size(data.len())
        .map_err(|_e| CoreError::ResourceExceeded("message exceeds resource limit".to_string()))?;
    let pk = uncompressed_public_key(public_key)?;
    facade_result(p384_verify::verify_ecdsa_p384_sha384_fixed(&pk, data, signature))
}

/// Verify an ECDSA-P384 signature over a pre-computed digest — e.g. the SHA-384 of
/// a COSE `Sig_structure`. `prehash` is the 48-byte SHA-384 digest, not the
/// message. A non-matching or malformed signature returns `Ok(false)`.
///
/// # Errors
/// Returns an error on an invalid public key, a `prehash` that is not 48 bytes,
/// or an invalid session.
pub fn verify_ecdsa_p384_prehash(
    prehash: &[u8],
    signature: &[u8],
    public_key: &[u8],
    mode: SecurityMode,
) -> Result<bool> {
    super::api::fips_verify_operational()?;
    mode.validate()?;
    let pk = uncompressed_public_key(public_key)?;
    let digest = sha384_prehash(prehash)?;
    facade_result(p384_verify::verify_ecdsa_p384_sha384_prehash_fixed(&pk, digest, signature))
}

/// Verify an ECDSA-P384 signature supplied as an ASN.1 DER `SEQUENCE { r, s }`
/// over a pre-computed digest — e.g. an X.509 certificate-chain link signature
/// (the `signatureValue` BIT STRING content), as distinct from the fixed-width
/// `r‖s` form a COSE_Sign1 envelope carries. `prehash` is the digest (SHA-384 of
/// the certificate's TBS bytes), not the message. A non-matching or malformed
/// signature returns `Ok(false)`.
///
/// # Errors
/// Returns an error on an invalid public key, a `prehash` that is not 48 bytes,
/// or an invalid session.
pub fn verify_ecdsa_p384_prehash_der(
    prehash: &[u8],
    signature_der: &[u8],
    public_key: &[u8],
    mode: SecurityMode,
) -> Result<bool> {
    super::api::fips_verify_operational()?;
    mode.validate()?;
    let pk = uncompressed_public_key(public_key)?;
    let digest = sha384_prehash(prehash)?;
    facade_result(p384_verify::verify_ecdsa_p384_sha384_prehash(&pk, digest, signature_der))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keypair() -> Option<(Vec<u8>, Zeroizing<Vec<u8>>)> {
        generate_ecdsa_p384_keypair(SecurityMode::Unverified).ok()
    }

    #[test]
    fn sign_verify_roundtrip() {
        let Some((pk, sk)) = keypair() else { return };
        let msg = b"latticearc p384 facade roundtrip";
        let Ok(sig) = sign_ecdsa_p384(msg, &sk, SecurityMode::Unverified) else {
            return;
        };
        assert_eq!(sig.len(), ECDSA_P384_SIGNATURE_LEN);
        assert_eq!(verify_ecdsa_p384(msg, &sig, &pk, SecurityMode::Unverified).ok(), Some(true));
    }

    #[test]
    fn rejects_tampered_message() {
        let Some((pk, sk)) = keypair() else { return };
        let Ok(sig) = sign_ecdsa_p384(b"original", &sk, SecurityMode::Unverified) else {
            return;
        };
        assert_eq!(
            verify_ecdsa_p384(b"tampered", &sig, &pk, SecurityMode::Unverified).ok(),
            Some(false)
        );
    }

    #[test]
    fn prehash_verifies_sha384_digest() {
        use sha2::{Digest, Sha384};
        let Some((pk, sk)) = keypair() else { return };
        let msg = b"prehash payload";
        // ECDSA-P384 signs SHA-384(msg), so verify_prehash over SHA-384(msg) matches.
        let Ok(sig) = sign_ecdsa_p384(msg, &sk, SecurityMode::Unverified) else {
            return;
        };
        let digest = Sha384::digest(msg);
        assert_eq!(
            verify_ecdsa_p384_prehash(&digest, &sig, &pk, SecurityMode::Unverified).ok(),
            Some(true)
        );
    }

    #[test]
    fn prehash_der_verifies_x509_style_signature() {
        use sha2::{Digest, Sha384};
        let Some((pk, sk)) = keypair() else { return };
        let tbs = b"to-be-signed certificate bytes";
        // Sign produces fixed-width r‖s; re-encode as ASN.1 DER to mirror the
        // X.509 `signatureValue` form that the cert-chain verifier hands in.
        let Ok(raw) = sign_ecdsa_p384(tbs, &sk, SecurityMode::Unverified) else {
            return;
        };
        let Some(sig) = Signature::from_slice(&raw).ok() else {
            return;
        };
        let der = sig.to_der();
        let digest = Sha384::digest(tbs);
        assert_eq!(
            verify_ecdsa_p384_prehash_der(&digest, der.as_bytes(), &pk, SecurityMode::Unverified)
                .ok(),
            Some(true)
        );
    }

    #[test]
    fn prehash_der_rejects_raw_signature() {
        // A fixed-width r‖s value is not valid DER — must be Ok(false), not panic.
        let Some((pk, sk)) = keypair() else { return };
        let Ok(raw) = sign_ecdsa_p384(b"m", &sk, SecurityMode::Unverified) else {
            return;
        };
        assert_eq!(
            verify_ecdsa_p384_prehash_der(&[0u8; 48], &raw, &pk, SecurityMode::Unverified).ok(),
            Some(false)
        );
    }

    #[test]
    fn malformed_signature_is_false_not_error() {
        let Some((pk, _sk)) = keypair() else { return };
        assert_eq!(
            verify_ecdsa_p384(b"m", &[0u8; 96], &pk, SecurityMode::Unverified).ok(),
            Some(false)
        );
    }

    #[test]
    fn invalid_public_key_errors() {
        assert!(verify_ecdsa_p384(b"m", &[0u8; 96], &[0u8; 10], SecurityMode::Unverified).is_err());
    }

    #[test]
    fn wrong_length_signature_is_false_not_error() {
        let Some((pk, _sk)) = keypair() else { return };
        assert_eq!(
            verify_ecdsa_p384(b"m", &[0u8; 95], &pk, SecurityMode::Unverified).ok(),
            Some(false)
        );
        assert_eq!(
            verify_ecdsa_p384_prehash_der(&[0u8; 48], &[], &pk, SecurityMode::Unverified).ok(),
            Some(false)
        );
    }

    #[test]
    fn compressed_public_key_still_verifies() {
        let Some((pk, sk)) = keypair() else { return };
        let Ok(vk) = VerifyingKey::from_sec1_bytes(&pk) else { return };
        let compressed = vk.to_sec1_point(true).as_bytes().to_vec();
        let msg = b"compressed key";
        let Ok(sig) = sign_ecdsa_p384(msg, &sk, SecurityMode::Unverified) else {
            return;
        };
        assert_eq!(
            verify_ecdsa_p384(msg, &sig, &compressed, SecurityMode::Unverified).ok(),
            Some(true)
        );
    }

    #[test]
    fn prehash_must_be_sha384_length() {
        let Some((pk, _sk)) = keypair() else { return };
        assert!(matches!(
            verify_ecdsa_p384_prehash(&[0u8; 32], &[0u8; 96], &pk, SecurityMode::Unverified),
            Err(CoreError::InvalidInput(_))
        ));
        assert!(matches!(
            verify_ecdsa_p384_prehash_der(&[0u8; 64], &[0u8; 8], &pk, SecurityMode::Unverified),
            Err(CoreError::InvalidInput(_))
        ));
    }
}
