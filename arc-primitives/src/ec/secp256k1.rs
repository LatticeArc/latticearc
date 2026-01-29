#![deny(unsafe_code)]
#![warn(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

//! # secp256k1 Elliptic Curve Operations
//!
//! secp256k1 ECDSA signature implementation using k256 crate.
//! Provides Bitcoin/Ethereum compatible secp256k1 operations.

use super::traits::{EcKeyPair, EcSignature};
use arc_prelude::error::{LatticeArcError, Result};
use k256::ecdsa::{Signature, SigningKey, VerifyingKey, signature::Signer, signature::Verifier};
use rand::rngs::OsRng;

/// secp256k1 key pair implementation
#[derive(Clone)]
pub struct Secp256k1KeyPair {
    public_key: VerifyingKey,
    secret_key: SigningKey,
}

impl EcKeyPair for Secp256k1KeyPair {
    type PublicKey = VerifyingKey;
    type SecretKey = SigningKey;

    fn generate() -> Result<Self> {
        let secret_key = SigningKey::random(&mut OsRng {});
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

        let secret_key = SigningKey::from_bytes(secret_key_bytes.into())
            .map_err(|e| LatticeArcError::KeyGenerationError(e.to_string()))?;

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
        self.public_key.to_encoded_point(false).as_bytes().to_vec()
    }

    fn secret_key_bytes(&self) -> Vec<u8> {
        self.secret_key.to_bytes().to_vec()
    }
}

/// secp256k1 ECDSA signature operations
pub struct Secp256k1Signature;

impl EcSignature for Secp256k1Signature {
    type Signature = Signature;

    fn sign(&self, _message: &[u8]) -> Result<Self::Signature> {
        Err(LatticeArcError::InvalidOperation(
            "Use Secp256k1KeyPair::sign method instead".to_string(),
        ))
    }

    fn verify(public_key_bytes: &[u8], message: &[u8], signature: &Self::Signature) -> Result<()> {
        let public_key = VerifyingKey::from_sec1_bytes(public_key_bytes)
            .map_err(|e| LatticeArcError::InvalidKey(e.to_string()))?;

        public_key
            .verify(message, signature)
            .map_err(|e| LatticeArcError::SignatureVerificationError(e.to_string()))
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
    fn test_secp256k1_keypair_generation() -> Result<()> {
        let keypair = Secp256k1KeyPair::generate()?;
        assert_eq!(keypair.secret_key_bytes().len(), 32);
        // Uncompressed public key is 65 bytes (0x04 + x + y)
        assert_eq!(keypair.public_key_bytes().len(), 65);
        Ok(())
    }

    #[test]
    fn test_secp256k1_keypair_from_secret() -> Result<()> {
        let original = Secp256k1KeyPair::generate()?;
        let secret_bytes = original.secret_key_bytes();
        let reconstructed = Secp256k1KeyPair::from_secret_key(&secret_bytes)?;

        assert_eq!(original.public_key_bytes(), reconstructed.public_key_bytes());
        Ok(())
    }

    #[test]
    fn test_secp256k1_sign_verify() -> Result<()> {
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
    fn test_secp256k1_signature_serialization() -> Result<()> {
        let keypair = Secp256k1KeyPair::generate()?;
        let message = b"Test message";
        let signature = keypair.sign(message)?;

        let sig_bytes = Secp256k1Signature::signature_bytes(&signature);
        assert_eq!(sig_bytes.len(), 64);

        let reconstructed_sig = Secp256k1Signature::signature_from_bytes(&sig_bytes)?;
        assert_eq!(signature, reconstructed_sig);

        Ok(())
    }
}
