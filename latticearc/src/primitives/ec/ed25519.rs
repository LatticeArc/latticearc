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
use crate::primitives::rand::secure_rng;
use crate::primitives::resource_limits::validate_signature_size;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::digest::{FixedOutput, HashMarker, Output, OutputSizeUser, Update, consts::U64};
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
        // `ed25519_dalek::SigningKey::to_bytes()` returns a plain
        // `[u8; 32]` — no Zeroize wrapper, no `Drop` impl that wipes
        // the stack slot. Calling it directly inline (the previous
        // shape) materialised the 32-byte Ed25519 secret-key seed in
        // a stack temporary that stayed resident until the next call
        // overwrote it. Wrap each in `Zeroizing<[u8; 32]>` so the
        // stack slots are wiped when this function returns. Same
        // pattern as `zkp::schnorr::SchnorrProver::new` (which
        // documents the rationale at length).
        use zeroize::Zeroizing;
        let lhs: Zeroizing<[u8; 32]> = Zeroizing::new(self.secret_key.to_bytes());
        let rhs: Zeroizing<[u8; 32]> = Zeroizing::new(other.secret_key.to_bytes());
        lhs.as_ref().ct_eq(rhs.as_ref())
    }
}

impl EcKeyPair for Ed25519KeyPair {
    fn generate() -> Result<Self> {
        let secret_key = SigningKey::generate(&mut secure_rng());
        let public_key = VerifyingKey::from(&secret_key);

        let keypair = Self { public_key, secret_key };

        // Pairwise Consistency Test (PCT).
        // upstream PctError -> opaque KeyGenerationError so that variant
        // wording from the `pct` module isn't relayed verbatim.
        crate::primitives::pct::pct_ed25519(&keypair).map_err(|e| {
            tracing::debug!(error = %e, "Ed25519 keygen PCT failed");
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
            tracing::debug!(error = %e, "Ed25519 from_secret_key PCT failed");
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
            tracing::debug!(error = %e, msg_len = message.len(), "Ed25519 verify rejected: message exceeds resource limit");
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
            tracing::debug!(error = %e, "Ed25519 verify rejected: PK parse");
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
        // `Ok(..)` wrapper here exists for trait-shape parity with other
        // signature schemes (ML-DSA, SLH-DSA, FN-DSA) whose `from_bytes`
        // can fail at parse time. Removing the wrapper breaks the trait's
        // `Result` return type — leave it.
        Ok(Signature::from_bytes(&sig_bytes))
    }
}

/// Maximum Ed25519ph context length (RFC 8032 §5.1, `dom2(x, y)` encodes
/// `|y|` in one byte).
pub const ED25519PH_MAX_CONTEXT_LEN: usize = 255;

/// A finished SHA-512 digest presented through the `digest` traits so it can
/// be handed to `ed25519-dalek`'s Ed25519ph entry points, which take the
/// pre-hash as a `Digest<OutputSize = U64>` *state* rather than as bytes.
///
/// `finalize` yields the wrapped 64 bytes unchanged. `update` is a no-op:
/// the wrapper carries an already-final digest and `sign_prehashed` /
/// `verify_prehashed_strict` never call `update` on it (they only finalize).
/// It is crate-private and constructed solely by the two functions below.
#[derive(Clone)]
struct PrehashedSha512 {
    digest: [u8; 64],
}

// `Digest`'s blanket impl requires `Default`; `[u8; 64]` has none, so spell
// it out. Never reached by the two callers below, which always construct the
// wrapper with a real digest.
impl Default for PrehashedSha512 {
    fn default() -> Self {
        Self { digest: [0u8; 64] }
    }
}

impl Update for PrehashedSha512 {
    fn update(&mut self, _data: &[u8]) {}
}

impl OutputSizeUser for PrehashedSha512 {
    type OutputSize = U64;
}

impl FixedOutput for PrehashedSha512 {
    fn finalize_into(self, out: &mut Output<Self>) {
        out.copy_from_slice(&self.digest);
    }
}

impl HashMarker for PrehashedSha512 {}

impl Ed25519Signature {
    /// Verify an Ed25519ph (RFC 8032 §5.1) signature over a caller-supplied
    /// SHA-512 digest with the same `context` used at signing.
    ///
    /// Uses `verify_prehashed_strict`, matching the canonical-signature
    /// posture of [`EcSignature::verify`]. All verify-side failures collapse
    /// to the same opaque `SignatureVerificationError` except the
    /// non-adversarial argument checks.
    ///
    /// # Errors
    /// Returns `InvalidParameter` if `context` is empty or longer than 255
    /// bytes, `InvalidKeyLength` if `public_key_bytes` is not 32 bytes,
    /// `InvalidKey` if the key is not on the curve, and
    /// `SignatureVerificationError` if the signature does not verify.
    pub fn verify_prehashed(
        public_key_bytes: &[u8],
        digest: &[u8; 64],
        context: &[u8],
        signature: &Signature,
    ) -> Result<()> {
        if context.is_empty() || context.len() > ED25519PH_MAX_CONTEXT_LEN {
            return Err(LatticeArcError::InvalidParameter(format!(
                "Ed25519ph context must be 1..={ED25519PH_MAX_CONTEXT_LEN} bytes, got {}",
                context.len()
            )));
        }
        if public_key_bytes.len() != 32 {
            return Err(LatticeArcError::InvalidKeyLength {
                expected: 32,
                actual: public_key_bytes.len(),
            });
        }
        let mut pk_bytes = [0u8; 32];
        pk_bytes.copy_from_slice(public_key_bytes);
        let public_key = VerifyingKey::from_bytes(&pk_bytes).map_err(|e| {
            tracing::debug!(error = %e, "Ed25519ph verify rejected: PK parse");
            LatticeArcError::InvalidKey("invalid public key".to_string())
        })?;
        public_key
            .verify_prehashed_strict(PrehashedSha512 { digest: *digest }, Some(context), signature)
            .map_err(|_e| {
                LatticeArcError::SignatureVerificationError(
                    "Ed25519ph verification failed".to_string(),
                )
            })
    }
}

impl Ed25519KeyPair {
    /// Sign a caller-supplied SHA-512 digest with Ed25519ph (RFC 8032 §5.1,
    /// `dom2(1, context)` prefix) — the pre-hashed Ed25519 variant.
    ///
    /// `digest` is `SHA-512(M)` computed by the caller (streaming, any size);
    /// no message-size limit applies because this function never sees `M`.
    /// `context` is the RFC 8032 context string: non-empty and at most
    /// [`ED25519PH_MAX_CONTEXT_LEN`] bytes. An Ed25519ph signature never
    /// verifies as a pure Ed25519 signature over the same bytes and vice
    /// versa — the `dom2` prefix binds the mode.
    ///
    /// # Errors
    /// Returns `InvalidParameter` if `context` is empty or longer than 255
    /// bytes, and `SigningError` if `ed25519-dalek` rejects the input.
    pub fn sign_prehashed(&self, digest: &[u8; 64], context: &[u8]) -> Result<Signature> {
        if context.is_empty() || context.len() > ED25519PH_MAX_CONTEXT_LEN {
            return Err(LatticeArcError::InvalidParameter(format!(
                "Ed25519ph context must be 1..={ED25519PH_MAX_CONTEXT_LEN} bytes, got {}",
                context.len()
            )));
        }
        self.secret_key.sign_prehashed(PrehashedSha512 { digest: *digest }, Some(context)).map_err(
            |e| {
                tracing::debug!(error = %e, "Ed25519ph sign rejected");
                LatticeArcError::SigningError("Ed25519ph signing failed".to_string())
            },
        )
    }

    /// Sign a message with this key pair.
    ///
    /// Ed25519 signing itself is infallible for valid key pairs (which
    /// this type guarantees by construction); the only failure path is
    /// the resource-limit gate that bounds the message length to
    /// `max_signature_size_bytes` (default 64 KiB) before SHA-512
    /// hashes the payload (RFC 8032 §5.1.6).
    /// added this gate to close the unbounded-hash DoS that previously
    /// existed on the sign path.
    ///
    /// # Errors
    /// Returns `SignatureGenerationError` if `message.len()` exceeds
    /// the configured signature size limit.
    pub fn sign(&self, message: &[u8]) -> Result<Signature> {
        if let Err(e) = validate_signature_size(message.len()) {
            tracing::debug!(error = %e, msg_len = message.len(), "Ed25519 sign rejected: message exceeds resource limit");
            return Err(LatticeArcError::MessageTooLong);
        }
        Ok(self.secret_key.sign(message))
    }
}

#[cfg(test)]
#[expect(clippy::panic_in_result_fn, reason = "Tests use assertions for verification")]
#[expect(clippy::indexing_slicing, reason = "Tests use direct indexing")]
#[expect(clippy::expect_used, reason = "Tests use expect for simplicity")]
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
            let message = format!("Message number {i}");
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

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests use unwrap on statically valid inputs")]
#[expect(clippy::expect_used, reason = "tests use expect for clarity")]
mod prehashed_tests {
    use super::*;
    use sha2::{Digest, Sha512};

    fn sha512(m: &[u8]) -> [u8; 64] {
        Sha512::digest(m).into()
    }

    #[test]
    fn ed25519ph_roundtrip_and_context_binding() {
        let kp = Ed25519KeyPair::generate().unwrap();
        let pk = kp.public_key_bytes();
        let digest = sha512(b"large content");
        let sig = kp.sign_prehashed(&digest, b"vault/v1/inbox").unwrap();
        Ed25519Signature::verify_prehashed(&pk, &digest, b"vault/v1/inbox", &sig).unwrap();
        assert!(
            Ed25519Signature::verify_prehashed(&pk, &digest, b"vault/v1/transfer", &sig).is_err()
        );
        assert!(
            Ed25519Signature::verify_prehashed(&pk, &sha512(b"x"), b"vault/v1/inbox", &sig)
                .is_err()
        );
        let other = Ed25519KeyPair::generate().unwrap();
        assert!(
            Ed25519Signature::verify_prehashed(
                &other.public_key_bytes(),
                &digest,
                b"vault/v1/inbox",
                &sig
            )
            .is_err()
        );
    }

    #[test]
    fn ed25519ph_rejects_empty_and_oversized_context() {
        let kp = Ed25519KeyPair::generate().unwrap();
        let digest = sha512(b"m");
        for ctx in [&[][..], &[1u8; 256][..]] {
            let err = kp.sign_prehashed(&digest, ctx).unwrap_err();
            assert!(matches!(err, LatticeArcError::InvalidParameter(_)), "{err:?}");
        }
        let sig = kp.sign_prehashed(&digest, b"c").unwrap();
        for ctx in [&[][..], &[1u8; 256][..]] {
            let err =
                Ed25519Signature::verify_prehashed(&kp.public_key_bytes(), &digest, ctx, &sig)
                    .unwrap_err();
            assert!(matches!(err, LatticeArcError::InvalidParameter(_)), "{err:?}");
        }
        let max = [2u8; ED25519PH_MAX_CONTEXT_LEN];
        let sig = kp.sign_prehashed(&digest, &max).unwrap();
        Ed25519Signature::verify_prehashed(&kp.public_key_bytes(), &digest, &max, &sig).unwrap();
    }

    #[test]
    fn ed25519ph_verify_rejects_bad_public_key_inputs() {
        let kp = Ed25519KeyPair::generate().unwrap();
        let digest = sha512(b"m");
        let sig = kp.sign_prehashed(&digest, b"c").unwrap();
        let err = Ed25519Signature::verify_prehashed(&[0u8; 31], &digest, b"c", &sig).unwrap_err();
        assert!(matches!(err, LatticeArcError::InvalidKeyLength { expected: 32, actual: 31 }));
        // Find an encoding that does not decompress to a curve point (about
        // half of all 32-byte strings fail), then make sure it is reported
        // as an invalid key rather than as a verification failure.
        let bad_pk = (0u8..=255)
            .map(|k| [k; 32])
            .find(|cand| VerifyingKey::from_bytes(cand).is_err())
            .expect("some constant byte pattern is not a valid Ed25519 point");
        let err = Ed25519Signature::verify_prehashed(&bad_pk, &digest, b"c", &sig).unwrap_err();
        assert!(matches!(err, LatticeArcError::InvalidKey(_)), "{err:?}");
    }

    #[test]
    fn ed25519ph_and_pure_ed25519_never_cross_verify() {
        let kp = Ed25519KeyPair::generate().unwrap();
        let pk = kp.public_key_bytes();
        let digest = sha512(b"m");
        let pure = kp.sign(&digest).unwrap();
        assert!(Ed25519Signature::verify_prehashed(&pk, &digest, b"c", &pure).is_err());
        let ph = kp.sign_prehashed(&digest, b"c").unwrap();
        assert!(Ed25519Signature::verify(&pk, &digest, &ph).is_err());
    }

    /// RFC 8032 §7.3 Ed25519ph test vector (message "abc", no context).
    /// The public API requires a context, so this drives the crate-private
    /// digest wrapper straight into `ed25519-dalek` with `None` — proving
    /// the wrapper injects `PH(M)` exactly as the RFC's own SHA-512 would.
    #[test]
    fn ed25519ph_rfc8032_section_7_3_vector_via_digest_wrapper() {
        let secret =
            hex::decode("833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42")
                .unwrap();
        let expected_pk =
            hex::decode("ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf")
                .unwrap();
        let expected_sig = hex::decode(
            "98a70222f0b8121aa9d30f813d683f809e462b469c7ff87639499bb94e6dae41\
             31f85042463c2a355a2003d062adf5aaa10b8c61e636062aaad11c2a26083406",
        )
        .unwrap();
        let mut sk = [0u8; 32];
        sk.copy_from_slice(&secret);
        let signing_key = SigningKey::from_bytes(&sk);
        assert_eq!(signing_key.verifying_key().to_bytes().to_vec(), expected_pk);
        let digest = sha512(b"abc");
        let sig = signing_key
            .sign_prehashed(PrehashedSha512 { digest }, None)
            .expect("RFC vector must sign");
        assert_eq!(sig.to_bytes().to_vec(), expected_sig);
        signing_key
            .verifying_key()
            .verify_prehashed_strict(PrehashedSha512 { digest }, None, &sig)
            .expect("RFC vector must verify");
    }
}
