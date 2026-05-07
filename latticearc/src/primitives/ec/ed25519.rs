#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

//! # Ed25519 Elliptic Curve Operations
//!
//! Ed25519 signature implementation using ed25519-dalek crate.
//! Provides high-performance, RFC 8032 compliant Ed25519 signatures.

use super::traits::{EcKeyPair, EcSignature, sealed};
use crate::prelude::error::{LatticeArcError, Result};
use crate::primitives::resource_limits::validate_signature_size;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
// `ed25519-dalek 2.x` is pinned to `rand_core 0.6`; pass it the 0.6 OsRng
// (re-exported here as `OsRng`) so its `RngCore` bound is satisfied. Once
// the dalek 3.x stable line lands this can switch to plain `rand::rngs::OsRng`.
use rand_core_0_6::OsRng;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

// RFC 8032 §5.1.5 / §5.1.6 byte lengths, re-exported from `ed25519-dalek` so
// there is a single source of truth. These are re-exports rather than locally
// defined constants to guarantee they track the upstream crate's view of
// Ed25519 key and signature sizes.

/// Length of an Ed25519 public key in bytes.
pub use ed25519_dalek::PUBLIC_KEY_LENGTH as ED25519_PUBLIC_KEY_LEN;

/// Length of an Ed25519 secret key seed in bytes — the input to
/// [`ed25519_dalek::SigningKey::from_bytes`]. This is the seed, not the
/// expanded 64-byte form (seed || derived public key).
pub use ed25519_dalek::SECRET_KEY_LENGTH as ED25519_SECRET_KEY_LEN;

/// Length of an Ed25519 signature in bytes.
pub use ed25519_dalek::SIGNATURE_LENGTH as ED25519_SIGNATURE_LEN;

/// Ed25519 key pair implementation
///
/// The secret key is automatically zeroized on drop via `ed25519_dalek::SigningKey`'s
/// own `ZeroizeOnDrop` impl (enabled by the `zeroize` feature on `ed25519-dalek`).
pub struct Ed25519KeyPair {
    public_key: VerifyingKey,
    secret_key: SigningKey,
}

impl std::fmt::Debug for Ed25519KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ed25519KeyPair")
            .field("public_key", &self.public_key)
            .field("secret_key", &"[REDACTED]")
            .finish()
    }
}

impl ConstantTimeEq for Ed25519KeyPair {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.secret_key.to_bytes().ct_eq(&other.secret_key.to_bytes())
    }
}

impl EcKeyPair for Ed25519KeyPair {
    fn generate() -> Result<Self> {
        let secret_key = SigningKey::generate(&mut OsRng {});
        let public_key = VerifyingKey::from(&secret_key);

        let keypair = Self { public_key, secret_key };

        // Pairwise Consistency Test (PCT). audit fix (H9):
        // upstream PctError -> opaque KeyGenerationError so that variant
        // wording from the `pct` module isn't relayed verbatim.
        crate::primitives::pct::pct_ed25519(&keypair).map_err(|e| {
            tracing::debug!(error = ?e, "Ed25519 keygen PCT failed");
            LatticeArcError::KeyGenerationError("Ed25519 keypair PCT failed".to_string())
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

        let mut sk_bytes = Zeroizing::new([0u8; 32]);
        sk_bytes.copy_from_slice(secret_key_bytes);
        let secret_key = SigningKey::from_bytes(&sk_bytes);

        let public_key = VerifyingKey::from(&secret_key);

        let keypair = Self { public_key, secret_key };

        // FIPS 140-3 IG 10.3.A doesn't distinguish
        // key-introduction paths — every keypair entering the module
        // (whether via fresh generation or import from external bytes)
        // must run a Pairwise Consistency Test before exposure. Importing
        // a corrupted secret key was previously possible without
        // detection.
        // opaque error string.
        crate::primitives::pct::pct_ed25519(&keypair).map_err(|e| {
            tracing::debug!(error = ?e, "Ed25519 from_secret_key PCT failed");
            LatticeArcError::KeyGenerationError("Ed25519 keypair PCT failed".to_string())
        })?;

        Ok(keypair)
    }

    fn public_key_bytes(&self) -> Vec<u8> {
        self.public_key.to_bytes().to_vec()
    }

    fn secret_key_bytes(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.secret_key.to_bytes().to_vec())
    }
}

/// Ed25519 signature operations
pub struct Ed25519Signature;

impl sealed::Sealed for Ed25519KeyPair {}
impl sealed::Sealed for Ed25519Signature {}

impl EcSignature for Ed25519Signature {
    type Signature = Signature;

    /// Verify an Ed25519 signature.
    ///
    /// Uses `verify_strict` which rejects non-canonical signatures per
    /// RFC 8032 Section 8.4 (cofactor-less verification).
    ///
    /// # Errors
    /// Returns `InvalidKeyLength` if `public_key_bytes` is not exactly 32 bytes,
    /// `InvalidKey` if the public key is not on the Ed25519 curve, or
    /// `SignatureVerificationError` if the signature is invalid.
    fn verify(public_key_bytes: &[u8], message: &[u8], signature: &Self::Signature) -> Result<()> {
        // bound message length before SHA-512
        // hashes the entire payload (RFC 8032 §5.1.7 inner hash). Without
        // this, an attacker forces unbounded hashing through any verify
        // entrypoint — same DoS shape closed for ML-DSA /
        // SLH-DSA / FN-DSA.
        if let Err(e) = validate_signature_size(message.len()) {
            tracing::debug!(error = ?e, msg_len = message.len(), "Ed25519 verify rejected: message exceeds resource limit");
            return Err(LatticeArcError::SignatureVerificationError(
                "Ed25519 verification failed".to_string(),
            ));
        }

        if public_key_bytes.len() != 32 {
            return Err(LatticeArcError::InvalidKeyLength {
                expected: 32,
                actual: public_key_bytes.len(),
            });
        }
        let mut pk_bytes = [0u8; 32];
        pk_bytes.copy_from_slice(public_key_bytes);
        // opaque InvalidKey string. Upstream
        // dalek error variants are version-volatile; relaying them
        // verbatim is a side-channel into which check failed (off-curve
        // vs malformed encoding vs small-subgroup).
        let public_key = VerifyingKey::from_bytes(&pk_bytes).map_err(|e| {
            tracing::debug!(error = ?e, "Ed25519 verify rejected: PK parse");
            LatticeArcError::InvalidKey("invalid public key".to_string())
        })?;

        public_key.verify_strict(message, signature).map_err(|_e| {
            // Opaque error string to avoid leaking implementation details.
            LatticeArcError::SignatureVerificationError("Ed25519 verification failed".to_string())
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

        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(bytes);
        // `ed25519 v2.x`: `Signature::from_bytes(&[u8; 64]) -> Self` is
        // infallible (RFC 8032 defines no parse-time validity rule for the
        // 64-byte signature representation; validity is checked only at
        // verify time). The length check above is the only failure path; the
        // `Ok(...)` wrapper here exists for trait-shape parity with other
        // signature schemes (ML-DSA, SLH-DSA, FN-DSA) whose `from_bytes`
        // can fail at parse time. Removing the wrapper breaks the trait's
        // `Result` return type — leave it.
        Ok(Signature::from_bytes(&sig_bytes))
    }
}

impl Ed25519KeyPair {
    /// Sign a message with this key pair.
    ///
    /// Ed25519 signing itself is infallible for valid key pairs (which
    /// this type guarantees by construction); the only failure path is
    /// the resource-limit gate that bounds the message length to
    /// `max_signature_size_bytes` (default 64 KiB) before SHA-512
    /// hashes the payload (RFC 8032 §5.1.6). audit fix (H4)
    /// added this gate to close the unbounded-hash DoS that previously
    /// existed on the sign path.
    ///
    /// # Errors
    /// Returns `SignatureGenerationError` if `message.len()` exceeds
    /// the configured signature size limit.
    pub fn sign(&self, message: &[u8]) -> Result<Signature> {
        if let Err(e) = validate_signature_size(message.len()) {
            tracing::debug!(error = ?e, msg_len = message.len(), "Ed25519 sign rejected: message exceeds resource limit");
            return Err(LatticeArcError::MessageTooLong);
        }
        Ok(self.secret_key.sign(message))
    }
}

#[cfg(test)]
#[allow(clippy::panic_in_result_fn)] // Tests use assertions for verification
#[allow(clippy::indexing_slicing)] // Tests use direct indexing
#[allow(clippy::expect_used)] // Tests use expect for simplicity
mod tests {
    use super::*;
    use crate::prelude::error::Result;

    #[test]
    fn test_ed25519_keypair_generation_succeeds() -> Result<()> {
        let keypair = Ed25519KeyPair::generate()?;
        assert_eq!(keypair.public_key_bytes().len(), 32);
        assert_eq!(keypair.secret_key_bytes().len(), 32);
        Ok(())
    }

    #[test]
    fn test_ed25519_keypair_from_secret_roundtrip() -> Result<()> {
        let original = Ed25519KeyPair::generate()?;
        let secret_bytes = original.secret_key_bytes();
        let reconstructed = Ed25519KeyPair::from_secret_key(&secret_bytes)?;

        assert_eq!(original.public_key_bytes(), reconstructed.public_key_bytes());
        Ok(())
    }

    #[test]
    fn test_ed25519_sign_verify_roundtrip() -> Result<()> {
        let keypair = Ed25519KeyPair::generate()?;
        let message = b"Hello, Ed25519!";
        let signature = keypair.sign(message)?;

        let public_key_bytes = keypair.public_key_bytes();
        Ed25519Signature::verify(&public_key_bytes, message, &signature)?;

        // Test with wrong message
        let wrong_message = b"Wrong message";
        assert!(Ed25519Signature::verify(&public_key_bytes, wrong_message, &signature).is_err());

        Ok(())
    }

    #[test]
    fn test_ed25519_signature_serialization_roundtrip() -> Result<()> {
        let keypair = Ed25519KeyPair::generate()?;
        let message = b"Test message";
        let signature = keypair.sign(message)?;

        let sig_bytes = Ed25519Signature::signature_bytes(&signature);
        assert_eq!(sig_bytes.len(), 64);

        let reconstructed_sig = Ed25519Signature::signature_from_bytes(&sig_bytes)?;
        assert_eq!(signature, reconstructed_sig);

        Ok(())
    }

    // RFC 8032 test vectors
    #[test]
    fn test_ed25519_rfc8032_test_vector_1_matches_expected() -> Result<()> {
        // RFC 8032 Section 7.1, TEST 1 (empty message)
        let secret_key =
            hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
                .map_err(|e| LatticeArcError::InvalidKey(e.to_string()))?;
        let expected_public =
            hex::decode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
                .map_err(|e| LatticeArcError::InvalidKey(e.to_string()))?;
        let message = b"";
        let expected_signature = hex::decode(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155\
             5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        )
        .map_err(|e| LatticeArcError::InvalidKey(e.to_string()))?;

        let keypair = Ed25519KeyPair::from_secret_key(&secret_key)?;
        assert_eq!(keypair.public_key_bytes(), expected_public);

        let signature = keypair.sign(message)?;
        assert_eq!(Ed25519Signature::signature_bytes(&signature), expected_signature);

        Ed25519Signature::verify(&expected_public, message, &signature)?;
        Ok(())
    }

    #[test]
    fn test_ed25519_rfc8032_test_vector_2_matches_expected() -> Result<()> {
        // RFC 8032 Section 7.1, TEST 2 (1-byte message)
        let secret_key =
            hex::decode("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
                .map_err(|e| LatticeArcError::InvalidKey(e.to_string()))?;
        let expected_public =
            hex::decode("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")
                .map_err(|e| LatticeArcError::InvalidKey(e.to_string()))?;
        let message = hex::decode("72").map_err(|e| LatticeArcError::InvalidKey(e.to_string()))?;
        let expected_signature = hex::decode(
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da\
             085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
        )
        .map_err(|e| LatticeArcError::InvalidKey(e.to_string()))?;

        let keypair = Ed25519KeyPair::from_secret_key(&secret_key)?;
        assert_eq!(keypair.public_key_bytes(), expected_public);

        let signature = keypair.sign(&message)?;
        assert_eq!(Ed25519Signature::signature_bytes(&signature), expected_signature);

        Ed25519Signature::verify(&expected_public, &message, &signature)?;
        Ok(())
    }

    #[test]
    fn test_ed25519_rfc8032_test_vector_3_matches_expected() -> Result<()> {
        // RFC 8032 Section 7.1, TEST 3 (2-byte message)
        let secret_key =
            hex::decode("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7")
                .map_err(|e| LatticeArcError::InvalidKey(e.to_string()))?;
        let expected_public =
            hex::decode("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025")
                .map_err(|e| LatticeArcError::InvalidKey(e.to_string()))?;
        let message =
            hex::decode("af82").map_err(|e| LatticeArcError::InvalidKey(e.to_string()))?;
        let expected_signature = hex::decode(
            "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac\
             18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
        )
        .map_err(|e| LatticeArcError::InvalidKey(e.to_string()))?;

        let keypair = Ed25519KeyPair::from_secret_key(&secret_key)?;
        assert_eq!(keypair.public_key_bytes(), expected_public);

        let signature = keypair.sign(&message)?;
        assert_eq!(Ed25519Signature::signature_bytes(&signature), expected_signature);

        Ed25519Signature::verify(&expected_public, &message, &signature)?;
        Ok(())
    }

    // Corrupted signature tests
    #[test]
    fn test_ed25519_corrupted_signature_fails_verification_fails() -> Result<()> {
        let keypair = Ed25519KeyPair::generate()?;
        let message = b"Test message for corruption";
        let signature = keypair.sign(message)?;
        let mut sig_bytes = Ed25519Signature::signature_bytes(&signature);

        // Corrupt first byte
        sig_bytes[0] ^= 0xFF;
        let corrupted_sig = Ed25519Signature::signature_from_bytes(&sig_bytes)?;
        assert!(
            Ed25519Signature::verify(&keypair.public_key_bytes(), message, &corrupted_sig).is_err()
        );

        Ok(())
    }

    #[test]
    fn test_ed25519_signature_with_wrong_public_key_fails() -> Result<()> {
        let keypair1 = Ed25519KeyPair::generate()?;
        let keypair2 = Ed25519KeyPair::generate()?;
        let message = b"Test message";
        let signature = keypair1.sign(message)?;

        // Verify with wrong public key should fail
        assert!(
            Ed25519Signature::verify(&keypair2.public_key_bytes(), message, &signature).is_err()
        );

        Ok(())
    }

    // Invalid input tests
    #[test]
    fn test_ed25519_invalid_secret_key_length_fails() {
        let invalid_secret = vec![0u8; 16]; // Wrong length
        let result = Ed25519KeyPair::from_secret_key(&invalid_secret);
        assert!(result.is_err());
    }

    #[test]
    fn test_ed25519_invalid_public_key_fails_verification_fails() {
        let keypair = Ed25519KeyPair::generate().expect("Key generation should succeed");
        let message = b"Test message";
        let signature = keypair.sign(message).expect("sign should succeed");

        // Invalid public key (all zeros)
        let invalid_pk = vec![0u8; 32];
        let result = Ed25519Signature::verify(&invalid_pk, message, &signature);
        assert!(result.is_err());
    }

    #[test]
    fn test_ed25519_invalid_signature_length_fails() {
        let invalid_sig = vec![0u8; 32]; // Should be 64
        let result = Ed25519Signature::signature_from_bytes(&invalid_sig);
        assert!(result.is_err());

        let too_long_sig = vec![0u8; 128]; // Should be 64
        let result = Ed25519Signature::signature_from_bytes(&too_long_sig);
        assert!(result.is_err());
    }

    // Signature malleability tests
    #[test]
    fn test_ed25519_signature_deterministic_produces_same_output_is_deterministic() -> Result<()> {
        let keypair = Ed25519KeyPair::generate()?;
        let message = b"Test message for determinism";

        // Ed25519 signatures are deterministic
        let sig1 = keypair.sign(message)?;
        let sig2 = keypair.sign(message)?;

        assert_eq!(
            Ed25519Signature::signature_bytes(&sig1),
            Ed25519Signature::signature_bytes(&sig2)
        );

        Ok(())
    }

    #[test]
    fn test_ed25519_empty_message_roundtrip() -> Result<()> {
        let keypair = Ed25519KeyPair::generate()?;
        let message = b"";
        let signature = keypair.sign(message)?;

        Ed25519Signature::verify(&keypair.public_key_bytes(), message, &signature)?;
        Ok(())
    }

    #[test]
    fn test_ed25519_large_message_roundtrip() -> Result<()> {
        let keypair = Ed25519KeyPair::generate()?;
        let message = vec![0xAB; 10_000]; // 10KB message
        let signature = keypair.sign(&message)?;

        Ed25519Signature::verify(&keypair.public_key_bytes(), &message, &signature)?;
        Ok(())
    }

    #[test]
    fn test_ed25519_multiple_messages_same_keypair_succeeds() -> Result<()> {
        let keypair = Ed25519KeyPair::generate()?;

        for i in 0..10 {
            let message = format!("Message number {}", i);
            let signature = keypair.sign(message.as_bytes())?;
            Ed25519Signature::verify(&keypair.public_key_bytes(), message.as_bytes(), &signature)?;
        }

        Ok(())
    }

    #[test]
    fn test_ed25519_signature_size_is_correct() {
        assert_eq!(Ed25519Signature::signature_len(), 64);
    }

    #[test]
    fn test_ed25519_from_secret_key_too_long_fails() {
        let too_long = vec![0u8; 64];
        let result = Ed25519KeyPair::from_secret_key(&too_long);
        assert!(result.is_err());
    }
}
