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
        SigningKey::from_bytes((&self.secret_bytes[..]).into())
            .map_err(|e| LatticeArcError::KeyGenerationError(e.to_string()))
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

        // Pairwise Consistency Test (PCT)
        crate::primitives::pct::pct_secp256k1(&keypair)
            .map_err(|e| LatticeArcError::KeyGenerationError(e.to_string()))?;

        Ok(keypair)
    }

    fn from_secret_key(secret_key_bytes: &[u8]) -> Result<Self> {
        if secret_key_bytes.len() != 32 {
            return Err(LatticeArcError::InvalidKeyLength {
                expected: 32,
                actual: secret_key_bytes.len(),
            });
        }

        // Validate that the bytes form a valid scalar
        let sk = SigningKey::from_bytes(secret_key_bytes.into())
            .map_err(|e| LatticeArcError::KeyGenerationError(e.to_string()))?;
        let public_key = VerifyingKey::from(&sk);
        drop(sk);

        let mut secret_bytes = Zeroizing::new([0u8; 32]);
        secret_bytes.copy_from_slice(secret_key_bytes);

        Ok(Self { public_key, secret_bytes })
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
        let public_key = VerifyingKey::from_sec1_bytes(public_key_bytes)
            .map_err(|e| LatticeArcError::InvalidKey(e.to_string()))?;

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

        Signature::from_bytes(bytes.into())
            .map_err(|e| LatticeArcError::InvalidSignature(e.to_string()))
    }
}

impl Secp256k1KeyPair {
    /// Sign a message with this key pair using deterministic ECDSA (RFC 6979).
    ///
    /// # Errors
    /// Returns an error if the stored secret bytes cannot be reconstructed as a
    /// valid signing key (only possible if the internal state is corrupted).
    pub fn sign(&self, message: &[u8]) -> Result<Signature> {
        // Reconstruct a transient SigningKey from the zeroized byte buffer.
        // The SigningKey is dropped at end of function, leaving only the zeroized bytes.
        let sk = self.signing_key()?;
        Ok(sk.sign(message))
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
}
