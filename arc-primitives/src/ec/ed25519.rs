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
#[allow(clippy::indexing_slicing)] // Tests use direct indexing
#[allow(clippy::expect_used)] // Tests use expect for simplicity
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

    // RFC 8032 test vectors
    #[test]
    fn test_ed25519_rfc8032_test_vector_1() -> Result<()> {
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
    fn test_ed25519_rfc8032_test_vector_2() -> Result<()> {
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
    fn test_ed25519_rfc8032_test_vector_3() -> Result<()> {
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
    fn test_ed25519_corrupted_signature() -> Result<()> {
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
    fn test_ed25519_signature_with_wrong_public_key() -> Result<()> {
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
    fn test_ed25519_invalid_secret_key_length() {
        let invalid_secret = vec![0u8; 16]; // Wrong length
        let result = Ed25519KeyPair::from_secret_key(&invalid_secret);
        assert!(result.is_err());
    }

    #[test]
    fn test_ed25519_invalid_public_key() {
        let keypair = Ed25519KeyPair::generate().expect("Key generation should succeed");
        let message = b"Test message";
        let signature = keypair.sign(message).expect("Signing should succeed");

        // Invalid public key (all zeros)
        let invalid_pk = vec![0u8; 32];
        let result = Ed25519Signature::verify(&invalid_pk, message, &signature);
        assert!(result.is_err());
    }

    #[test]
    fn test_ed25519_invalid_signature_length() {
        let invalid_sig = vec![0u8; 32]; // Should be 64
        let result = Ed25519Signature::signature_from_bytes(&invalid_sig);
        assert!(result.is_err());

        let too_long_sig = vec![0u8; 128]; // Should be 64
        let result = Ed25519Signature::signature_from_bytes(&too_long_sig);
        assert!(result.is_err());
    }

    // Signature malleability tests
    #[test]
    fn test_ed25519_signature_deterministic() -> Result<()> {
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
    fn test_ed25519_empty_message() -> Result<()> {
        let keypair = Ed25519KeyPair::generate()?;
        let message = b"";
        let signature = keypair.sign(message)?;

        Ed25519Signature::verify(&keypair.public_key_bytes(), message, &signature)?;
        Ok(())
    }

    #[test]
    fn test_ed25519_large_message() -> Result<()> {
        let keypair = Ed25519KeyPair::generate()?;
        let message = vec![0xAB; 10_000]; // 10KB message
        let signature = keypair.sign(&message)?;

        Ed25519Signature::verify(&keypair.public_key_bytes(), &message, &signature)?;
        Ok(())
    }

    #[test]
    fn test_ed25519_multiple_messages_same_keypair() -> Result<()> {
        let keypair = Ed25519KeyPair::generate()?;

        for i in 0..10 {
            let message = format!("Message number {}", i);
            let signature = keypair.sign(message.as_bytes())?;
            Ed25519Signature::verify(&keypair.public_key_bytes(), message.as_bytes(), &signature)?;
        }

        Ok(())
    }

    #[test]
    fn test_ed25519_signature_size() {
        assert_eq!(Ed25519Signature::signature_len(), 64);
    }
}
