#![deny(unsafe_code)]
#![warn(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

//! # Ed25519 Elliptic Curve Operations
//!
//! Ed25519 signature implementation using ed25519-dalek crate.
//! Provides high-performance, RFC 8032 compliant Ed25519 signatures.

use super::traits::{EcKeyPair, EcSignature};
use arc_prelude::error::{LatticeArcError, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;

/// Ed25519 key pair implementation
pub struct Ed25519KeyPair {
    public_key: VerifyingKey,
    secret_key: SigningKey,
}

impl EcKeyPair for Ed25519KeyPair {
    type PublicKey = VerifyingKey;
    type SecretKey = SigningKey;

    fn generate() -> Result<Self> {
        let secret_key = SigningKey::generate(&mut OsRng {});
        let public_key = VerifyingKey::from(&secret_key);

        Ok(Self { public_key, secret_key })
    }

    fn from_secret_key(secret_key_bytes: &[u8]) -> Result<Self> {
        if secret_key_bytes.len() != 32 {
            return Err(LatticeArcError::InvalidKeyLength {
                expected: 32,
                actual: secret_key_bytes.len(),
            });
        }

        let mut sk_bytes = [0u8; 32];
        sk_bytes.copy_from_slice(secret_key_bytes);
        let secret_key = SigningKey::from_bytes(&sk_bytes);

        let public_key = VerifyingKey::from(&secret_key);

        Ok(Self { public_key, secret_key })
    }

    fn public_key(&self) -> &Self::PublicKey {
        &self.public_key
    }

    fn secret_key(&self) -> &Self::SecretKey {
        &self.secret_key
    }

    fn public_key_bytes(&self) -> Vec<u8> {
        self.public_key.to_bytes().to_vec()
    }

    fn secret_key_bytes(&self) -> Vec<u8> {
        self.secret_key.to_bytes().to_vec()
    }
}

/// Ed25519 signature operations
pub struct Ed25519Signature;

impl EcSignature for Ed25519Signature {
    type Signature = Signature;

    fn sign(&self, _message: &[u8]) -> Result<Self::Signature> {
        // Note: This method expects self to be a keypair, but trait doesn't allow that
        // In practice, you'd call sign on a keypair instance
        Err(LatticeArcError::InvalidOperation(
            "Use Ed25519KeyPair::sign method instead".to_string(),
        ))
    }

    fn verify(public_key_bytes: &[u8], message: &[u8], signature: &Self::Signature) -> Result<()> {
        let mut pk_bytes = [0u8; 32];
        pk_bytes.copy_from_slice(public_key_bytes);
        let public_key = VerifyingKey::from_bytes(&pk_bytes)
            .map_err(|e| LatticeArcError::InvalidKey(e.to_string()))?;

        public_key.verify(message, signature).map_err(|_e| LatticeArcError::VerificationError)
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
        Ok(Signature::from_bytes(&sig_bytes))
    }
}

impl Ed25519KeyPair {
    /// Sign a message with this key pair.
    ///
    /// # Errors
    /// This function is infallible for valid key pairs but returns Result for API consistency.
    pub fn sign(&self, message: &[u8]) -> Result<Signature> {
        Ok(self.secret_key.sign(message))
    }
}

#[cfg(test)]
#[allow(clippy::panic_in_result_fn)] // Tests use assertions for verification
mod tests {
    use super::*;
    use arc_prelude::error::Result;

    #[test]
    fn test_ed25519_keypair_generation() -> Result<()> {
        let keypair = Ed25519KeyPair::generate()?;
        assert_eq!(keypair.public_key_bytes().len(), 32);
        assert_eq!(keypair.secret_key_bytes().len(), 32);
        Ok(())
    }

    #[test]
    fn test_ed25519_keypair_from_secret() -> Result<()> {
        let original = Ed25519KeyPair::generate()?;
        let secret_bytes = original.secret_key_bytes();
        let reconstructed = Ed25519KeyPair::from_secret_key(&secret_bytes)?;

        assert_eq!(original.public_key_bytes(), reconstructed.public_key_bytes());
        Ok(())
    }

    #[test]
    fn test_ed25519_sign_verify() -> Result<()> {
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
    fn test_ed25519_signature_serialization() -> Result<()> {
        let keypair = Ed25519KeyPair::generate()?;
        let message = b"Test message";
        let signature = keypair.sign(message)?;

        let sig_bytes = Ed25519Signature::signature_bytes(&signature);
        assert_eq!(sig_bytes.len(), 64);

        let reconstructed_sig = Ed25519Signature::signature_from_bytes(&sig_bytes)?;
        assert_eq!(signature, reconstructed_sig);

        Ok(())
    }
}
