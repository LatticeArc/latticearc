#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

//! # secp256k1 Elliptic Curve Operations
//!
//! secp256k1 ECDSA signature implementation using k256 crate.
//! Provides Bitcoin/Ethereum compatible secp256k1 operations.

use super::traits::{EcKeyPair, EcSignature, sealed};
use crate::prelude::error::{LatticeArcError, Result};
use crate::primitives::resource_limits::validate_signature_size;
use k256::ecdsa::{Signature, SigningKey, VerifyingKey, signature::Signer, signature::Verifier};
use rand_core_0_6::OsRng; // k256 uses rand_core 0.6
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// secp256k1 key pair implementation.
///
/// # Zeroization strategy
///
/// `k256 v0.13` does not expose a `zeroize` feature, so `k256::ecdsa::SigningKey`
/// does not implement `ZeroizeOnDrop`. To guarantee zeroization of secret material,
/// this type stores the raw key bytes in `Zeroizing<[u8; 32]>` (which zeroes on drop)
/// and reconstructs a transient `SigningKey` via `signing_key()` for each operation.
///
/// This type intentionally does not implement `Clone` to prevent
/// accidental duplication of secret key material.
pub struct Secp256k1KeyPair {
    public_key: VerifyingKey,
    /// Secret key bytes, automatically zeroized on drop.
    secret_bytes: Zeroizing<[u8; 32]>,
}

impl std::fmt::Debug for Secp256k1KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Secp256k1KeyPair")
            .field("public_key", &self.public_key)
            .field("secret_bytes", &"[REDACTED]")
            .finish()
    }
}

impl ConstantTimeEq for Secp256k1KeyPair {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.secret_bytes.ct_eq(&*other.secret_bytes)
    }
}

impl Secp256k1KeyPair {
    /// Construct a transient `SigningKey` from the stored bytes.
    ///
    /// The returned value must not outlive `self` conceptually; callers should
    /// use it immediately and drop it.
    fn signing_key(&self) -> Result<SigningKey> {
        // Round-26 audit fix (H9): opaque error string. Upstream k256
        // wording is version-volatile and would leak which exact
        // validity check failed (e.g. zero scalar vs out-of-range).
        SigningKey::from_bytes((&self.secret_bytes[..]).into()).map_err(|e| {
            tracing::debug!(error = ?e, "secp256k1 signing key reconstruction failed");
            LatticeArcError::KeyGenerationError("invalid secp256k1 secret key".to_string())
        })
    }
}

impl EcKeyPair for Secp256k1KeyPair {
    fn generate() -> Result<Self> {
        let sk = SigningKey::random(&mut OsRng {});
        let public_key = VerifyingKey::from(&sk);

        let mut secret_bytes = Zeroizing::new([0u8; 32]);
        secret_bytes.copy_from_slice(&sk.to_bytes());
        // `sk` drops here; we retain only the zeroized byte buffer.
        drop(sk);

        let keypair = Self { public_key, secret_bytes };

        // Pairwise Consistency Test (PCT). Round-26 audit fix (H9):
        // opaque KeyGenerationError so PctError variant wording is not
        // relayed verbatim.
        crate::primitives::pct::pct_secp256k1(&keypair).map_err(|e| {
            tracing::debug!(error = ?e, "secp256k1 keygen PCT failed");
            LatticeArcError::KeyGenerationError("secp256k1 keypair PCT failed".to_string())
        })?;

        Ok(keypair)
    }

    fn from_secret_key(secret_key_bytes: &[u8]) -> Result<Self> {
        if secret_key_bytes.len() != 32 {
            return Err(LatticeArcError::InvalidKeyLength {
                expected: 32,
                actual: secret_key_bytes.len(),
            });
        }

        // Validate that the bytes form a valid scalar. Round-26 audit
        // fix (H9): opaque error string for k256 validity failures.
        let sk = SigningKey::from_bytes(secret_key_bytes.into()).map_err(|e| {
            tracing::debug!(error = ?e, "secp256k1 from_secret_key parse failed");
            LatticeArcError::InvalidKey("invalid secp256k1 secret key".to_string())
        })?;
        let public_key = VerifyingKey::from(&sk);
        drop(sk);

        let mut secret_bytes = Zeroizing::new([0u8; 32]);
        secret_bytes.copy_from_slice(secret_key_bytes);

        let keypair = Self { public_key, secret_bytes };

        // Round-20 audit fix #3: FIPS 140-3 IG 10.3.A — every keypair
        // entering the module (fresh generation or import) must run PCT
        // before exposure. Symmetric with `generate()` above.
        // Round-26 audit fix (H9): opaque error string.
        crate::primitives::pct::pct_secp256k1(&keypair).map_err(|e| {
            tracing::debug!(error = ?e, "secp256k1 from_secret_key PCT failed");
            LatticeArcError::KeyGenerationError("secp256k1 keypair PCT failed".to_string())
        })?;

        Ok(keypair)
    }

    fn public_key_bytes(&self) -> Vec<u8> {
        self.public_key.to_encoded_point(false).as_bytes().to_vec()
    }

    fn secret_key_bytes(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.secret_bytes.to_vec())
    }
}

/// secp256k1 ECDSA signature operations
pub struct Secp256k1Signature;

impl sealed::Sealed for Secp256k1KeyPair {}
impl sealed::Sealed for Secp256k1Signature {}

impl EcSignature for Secp256k1Signature {
    type Signature = Signature;

    /// Verify a secp256k1 ECDSA signature.
    ///
    /// # Errors
    /// Returns `InvalidKey` if `public_key_bytes` is not a valid SEC1-encoded
    /// secp256k1 public key, or `SignatureVerificationError` if the signature
    /// is invalid. Error messages are opaque to avoid leaking internal state.
    fn verify(public_key_bytes: &[u8], message: &[u8], signature: &Self::Signature) -> Result<()> {
        // Round-26 audit fix (H6): bound message length before SHA-256
        // hashes the entire payload (RFC 6979 / ECDSA pre-hash). Same
        // DoS shape round-24 closed for ML-DSA / SLH-DSA / FN-DSA.
        if let Err(e) = validate_signature_size(message.len()) {
            tracing::debug!(error = ?e, msg_len = message.len(), "secp256k1 verify rejected: message exceeds resource limit");
            return Err(LatticeArcError::SignatureVerificationError(
                "secp256k1 verification failed".to_string(),
            ));
        }

        // Round-26 audit fix (H5): reject high-S (non-canonical)
        // signatures. ECDSA is malleable — k256's `Verifier::verify`
        // accepts both `(r, s)` and `(r, n - s)` because both verify.
        // For the BIP-146 / EIP-2 transaction-malleability surface this
        // crate is positioned for, downstream consumers that hash the
        // signature (txid pattern) need a canonical low-S form. Reject
        // high-S unconditionally here; callers that need legacy
        // behavior can re-normalize via `Signature::normalize_s` before
        // calling.
        if let Some(_normalized) = signature.normalize_s() {
            // `normalize_s()` returns `Some` when the input was high-S.
            tracing::debug!("secp256k1 verify rejected: high-S signature (BIP-146/EIP-2)");
            return Err(LatticeArcError::SignatureVerificationError(
                "secp256k1 verification failed".to_string(),
            ));
        }

        // Round-26 audit fix (L20): enforce a single canonical SEC1
        // form on the wire. `public_key_bytes()` always emits the
        // 65-byte uncompressed form (0x04 || X || Y); a permissive
        // `from_sec1_bytes` previously accepted compressed (33-byte,
        // 0x02 / 0x03 prefix) and the legacy hybrid (65-byte,
        // 0x06 / 0x07) forms, so the same key produced multiple
        // distinct identities when downstream consumers hashed the PK
        // bytes. Reject everything but the uncompressed form here.
        let canonical_pk = public_key_bytes.len() == 65 && public_key_bytes.first() == Some(&0x04);
        if !canonical_pk {
            tracing::debug!(
                pk_len = public_key_bytes.len(),
                "secp256k1 verify rejected: non-canonical SEC1 encoding"
            );
            return Err(LatticeArcError::InvalidKey("invalid public key".to_string()));
        }

        // Round-26 audit fix (H9): opaque InvalidKey string for SEC1
        // parse failures. k256 wording leaks which structural check
        // failed (length vs encoding vs not-on-curve).
        let public_key = VerifyingKey::from_sec1_bytes(public_key_bytes).map_err(|e| {
            tracing::debug!(error = ?e, "secp256k1 verify rejected: PK parse");
            LatticeArcError::InvalidKey("invalid public key".to_string())
        })?;

        public_key.verify(message, signature).map_err(|_e| {
            // Opaque error message: avoid leaking internal verification state.
            LatticeArcError::SignatureVerificationError("secp256k1 verification failed".to_string())
        })
    }

    fn signature_len() -> usize {
        64
    }

    fn signature_bytes(signature: &Self::Signature) -> Vec<u8> {
        signature.to_bytes().to_vec()
    }

    fn signature_from_bytes(bytes: &[u8]) -> Result<Self::Signature> {
        if bytes.len() != Self::signature_len() {
            return Err(LatticeArcError::InvalidSignatureLength {
                expected: Self::signature_len(),
                got: bytes.len(),
            });
        }

        // Round-26 audit fix (H9): opaque parse error string.
        let signature = Signature::from_bytes(bytes.into()).map_err(|e| {
            tracing::debug!(error = ?e, "secp256k1 signature parse failed");
            LatticeArcError::InvalidSignature("invalid secp256k1 signature".to_string())
        })?;

        // Round-26 audit fix (H5 / L19): reject high-S at parse time so
        // downstream code never sees malleable signatures. `normalize_s`
        // returns `Some` when the input was high-S; treat that as a
        // parse failure rather than silently canonicalizing, so the
        // wire format the producer chose is preserved or rejected (no
        // surprise rewrite).
        if signature.normalize_s().is_some() {
            tracing::debug!("secp256k1 signature_from_bytes rejected: high-S (BIP-146/EIP-2)");
            return Err(LatticeArcError::InvalidSignature(
                "invalid secp256k1 signature".to_string(),
            ));
        }

        Ok(signature)
    }
}

impl Secp256k1KeyPair {
    /// Sign a message with this key pair using deterministic ECDSA (RFC 6979).
    ///
    /// # Errors
    /// Returns an error if the stored secret bytes cannot be reconstructed as a
    /// valid signing key (only possible if the internal state is corrupted).
    pub fn sign(&self, message: &[u8]) -> Result<Signature> {
        // Round-26 audit fix (H6): bound message length before SHA-256
        // hashes the payload.
        if let Err(e) = validate_signature_size(message.len()) {
            tracing::debug!(error = ?e, msg_len = message.len(), "secp256k1 sign rejected: message exceeds resource limit");
            return Err(LatticeArcError::MessageTooLong);
        }

        // Reconstruct a transient SigningKey from the zeroized byte buffer.
        // The SigningKey is dropped at end of function, leaving only the zeroized bytes.
        let sk = self.signing_key()?;
        let signature: Signature = sk.sign(message);

        // Round-26 audit fix (H5): canonicalize the produced signature
        // to low-S so downstream consumers (BIP-146 / EIP-2 protocols
        // that hash the signature into a txid) see a single canonical
        // representation. `normalize_s` returns `Some(low_s)` when the
        // input was high-S and `None` when already low-S; either way,
        // the result returned is canonical.
        Ok(signature.normalize_s().unwrap_or(signature))
    }
}

#[cfg(test)]
#[allow(clippy::panic_in_result_fn)] // Tests use assertions for verification
mod tests {
    use super::*;
    use crate::prelude::error::Result;

    #[test]
    fn test_secp256k1_keypair_generation_succeeds() -> Result<()> {
        let keypair = Secp256k1KeyPair::generate()?;
        assert_eq!(keypair.secret_key_bytes().len(), 32);
        // Uncompressed public key is 65 bytes (0x04 + x + y)
        assert_eq!(keypair.public_key_bytes().len(), 65);
        Ok(())
    }

    #[test]
    fn test_secp256k1_keypair_from_secret_succeeds() -> Result<()> {
        let original = Secp256k1KeyPair::generate()?;
        let secret_bytes = original.secret_key_bytes();
        let reconstructed = Secp256k1KeyPair::from_secret_key(&secret_bytes)?;

        assert_eq!(original.public_key_bytes(), reconstructed.public_key_bytes());
        Ok(())
    }

    #[test]
    fn test_secp256k1_sign_verify_roundtrip() -> Result<()> {
        let keypair = Secp256k1KeyPair::generate()?;
        let message = b"Hello, secp256k1!";
        let signature = keypair.sign(message)?;

        let public_key_bytes = keypair.public_key_bytes();
        Secp256k1Signature::verify(&public_key_bytes, message, &signature)?;

        // Test with wrong message
        let wrong_message = b"Wrong message";
        assert!(Secp256k1Signature::verify(&public_key_bytes, wrong_message, &signature).is_err());

        Ok(())
    }

    #[test]
    fn test_secp256k1_signature_serialization_succeeds() -> Result<()> {
        let keypair = Secp256k1KeyPair::generate()?;
        let message = b"Test message";
        let signature = keypair.sign(message)?;

        let sig_bytes = Secp256k1Signature::signature_bytes(&signature);
        assert_eq!(sig_bytes.len(), 64);

        let reconstructed_sig = Secp256k1Signature::signature_from_bytes(&sig_bytes)?;
        assert_eq!(signature, reconstructed_sig);

        Ok(())
    }

    #[test]
    fn test_secp256k1_from_secret_key_invalid_length_fails() {
        let too_short = vec![0u8; 16];
        let result = Secp256k1KeyPair::from_secret_key(&too_short);
        assert!(result.is_err());

        let too_long = vec![0u8; 64];
        let result = Secp256k1KeyPair::from_secret_key(&too_long);
        assert!(result.is_err());
    }

    #[test]
    fn test_secp256k1_signature_from_bytes_invalid_length_fails() {
        let too_short = vec![0u8; 32];
        let result = Secp256k1Signature::signature_from_bytes(&too_short);
        assert!(result.is_err());

        let too_long = vec![0u8; 128];
        let result = Secp256k1Signature::signature_from_bytes(&too_long);
        assert!(result.is_err());
    }

    #[test]
    fn test_secp256k1_byte_accessors_return_correct_lengths_has_correct_size() -> Result<()> {
        let keypair = Secp256k1KeyPair::generate()?;
        assert_eq!(keypair.public_key_bytes().len(), 65);
        assert_eq!(keypair.secret_key_bytes().len(), 32);
        Ok(())
    }

    #[test]
    fn test_secp256k1_signature_len_is_64_bytes_succeeds() {
        assert_eq!(Secp256k1Signature::signature_len(), 64);
    }

    #[test]
    fn test_secp256k1_verify_invalid_public_key_fails() {
        let invalid_pk = vec![0u8; 10];
        let sig = Signature::from_bytes(&[0u8; 64].into());
        if let Ok(sig) = sig {
            let result = Secp256k1Signature::verify(&invalid_pk, b"test", &sig);
            assert!(result.is_err());
        }
    }

    // secp256k1 group order n in big-endian. Used to construct high-S
    // signatures by computing `n - s` for a given low-S `s`. Verified
    // against SECG SEC2 §2.4.1.
    const SECP256K1_ORDER_BE: [u8; 32] = [
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36,
        0x41, 0x41,
    ];

    /// Negate a 32-byte big-endian scalar mod n: returns `n - s`. Used to
    /// turn a canonical low-S signature into a malleable high-S form.
    fn negate_scalar_mod_n(s: [u8; 32]) -> [u8; 32] {
        // Big-endian subtraction `n - s` with borrow propagation. n > s
        // for any low-S input (s ≤ n/2), so no underflow.
        let mut result = [0u8; 32];
        let mut borrow: i16 = 0;
        for i in (0..32).rev() {
            let n_byte = SECP256K1_ORDER_BE[i] as i16;
            let s_byte = s[i] as i16;
            let mut diff = n_byte - s_byte - borrow;
            if diff < 0 {
                diff += 256;
                borrow = 1;
            } else {
                borrow = 0;
            }
            result[i] = diff as u8;
        }
        result
    }

    /// Round-27 H3: high-S signature bytes are rejected by
    /// `signature_from_bytes` (BIP-146 / EIP-2). The raw byte path is the
    /// one wire format consumers use, so this is the parse-time gate.
    #[test]
    fn test_secp256k1_high_s_signature_from_bytes_rejected() -> Result<()> {
        let keypair = Secp256k1KeyPair::generate()?;
        let message = b"high-S parse rejection test";
        let sig = keypair.sign(message)?;
        let mut sig_bytes = Secp256k1Signature::signature_bytes(&sig);

        // The k256 signer emits low-S by default. Negate s in place to
        // produce the high-S form `(r, n - s)`.
        let mut s_le = [0u8; 32];
        s_le.copy_from_slice(&sig_bytes[32..64]);
        let high_s = negate_scalar_mod_n(s_le);
        sig_bytes[32..64].copy_from_slice(&high_s);

        let parsed = Secp256k1Signature::signature_from_bytes(&sig_bytes);
        assert!(
            parsed.is_err(),
            "high-S signature must be rejected by signature_from_bytes (BIP-146/EIP-2)"
        );
        Ok(())
    }

    /// Round-27 H3: a high-S signature constructed in-process (bypassing
    /// the parse gate) is rejected by `verify`. This covers the in-memory
    /// path where a caller has already obtained a `Signature` value.
    #[test]
    fn test_secp256k1_high_s_signature_verify_rejected() -> Result<()> {
        let keypair = Secp256k1KeyPair::generate()?;
        let message = b"high-S verify rejection test";
        let sig = keypair.sign(message)?;
        let sig_bytes = Secp256k1Signature::signature_bytes(&sig);

        // Build the high-S form directly via k256, bypassing
        // signature_from_bytes which would reject it at parse time.
        let mut s_le = [0u8; 32];
        s_le.copy_from_slice(&sig_bytes[32..64]);
        let high_s = negate_scalar_mod_n(s_le);
        let mut high_sig_bytes = [0u8; 64];
        high_sig_bytes[..32].copy_from_slice(&sig_bytes[..32]);
        high_sig_bytes[32..].copy_from_slice(&high_s);

        // Construct via k256's low-level API (this does NOT reject high-S).
        let high_sig = Signature::from_slice(&high_sig_bytes)
            .map_err(|e| LatticeArcError::InvalidSignature(format!("test setup: {e}")))?;

        // Sanity: the test setup actually produced a high-S signature.
        assert!(
            high_sig.normalize_s().is_some(),
            "test setup bug: constructed signature is not high-S"
        );

        let pk_bytes = keypair.public_key_bytes();
        let result = Secp256k1Signature::verify(&pk_bytes, message, &high_sig);
        assert!(result.is_err(), "high-S signature must be rejected by verify (BIP-146/EIP-2)");
        Ok(())
    }

    /// Round-27 H3 sanity check: the `negate_scalar_mod_n` test helper
    /// must compute `n - s` correctly. Verified by checking that
    /// `negate(negate(s)) == s` for an arbitrary low-S scalar.
    #[test]
    fn test_negate_scalar_mod_n_is_involutive() {
        let s: [u8; 32] = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB,
            0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67,
            0x89, 0xAB, 0xCD, 0xEF,
        ];
        let high = negate_scalar_mod_n(s);
        let back = negate_scalar_mod_n(high);
        assert_eq!(back, s, "negate is not involutive — helper is broken");
    }
}
