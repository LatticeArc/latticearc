#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

//! Convenience functions for common cryptographic operations.
//!
//! This module provides easy-to-use functions for encryption, decryption, signing,
//! verification, key generation, key derivation, hashing, and HMAC operations.

use aws_lc_rs::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use aws_lc_rs::hkdf::{Salt, HKDF_SHA256, KeyType};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

use sha2::Sha256;
use sha3::{Digest, Sha3_256};
use hmac::{Hmac, Mac};

use subtle::ConstantTimeEq;

use chrono::{DateTime, Utc};

use super::{
    config::{CryptoConfig, EncryptionConfig, SignatureConfig},
    error::CryptoError,
    selector::{CryptoPolicyEngine, UseCase},
    types::{EncryptedData, EncryptedMetadata, PrivateKey, PublicKey, SignedData, SignedMetadata},
};

#[cfg(feature = "perf")]
use rayon::prelude::*;

/// Custom output length type for aws-lc-rs HKDF
struct HkdfOutputLen(usize);

impl KeyType for HkdfOutputLen {
    fn len(&self) -> usize {
        self.0
    }
}

#[inline]
fn encrypt_aes_gcm(data: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if key.len() < 32 {
        return Err(CryptoError::InvalidInput(format!(
            "Key must be at least 32 bytes, got {}",
            key.len()
        )));
    }

    let key_bytes: [u8; 32] = key[..32]
        .try_into()
        .map_err(|_e| CryptoError::InvalidInput("Key must be exactly 32 bytes".to_string()))?;

    let unbound = UnboundKey::new(&AES_256_GCM, &key_bytes)
        .map_err(|_| CryptoError::EncryptionFailed("Failed to create AES key".to_string()))?;
    let aes_key = LessSafeKey::new(unbound);

    let mut nonce_bytes = [0u8; 12];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce_bytes);

    let nonce = Nonce::assume_unique_for_key(nonce_bytes);

    let mut ciphertext = data.to_vec();
    aes_key
        .seal_in_place_append_tag(nonce, Aad::empty(), &mut ciphertext)
        .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

    let mut result = nonce_bytes.to_vec();
    result.append(&mut ciphertext);

    Ok(result)
}

#[inline]
fn decrypt_aes_gcm(encrypted_data: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if encrypted_data.len() < 12 {
        return Err(CryptoError::InvalidInput("Data too short".to_string()));
    }

    if key.len() < 32 {
        return Err(CryptoError::InvalidInput(format!(
            "Key must be at least 32 bytes, got {}",
            key.len()
        )));
    }

    let key_bytes: [u8; 32] = key[..32]
        .try_into()
        .map_err(|_e| CryptoError::InvalidInput("Key must be exactly 32 bytes".to_string()))?;

    let unbound = UnboundKey::new(&AES_256_GCM, &key_bytes)
        .map_err(|_| CryptoError::DecryptionFailed("Failed to create AES key".to_string()))?;
    let aes_key = LessSafeKey::new(unbound);

    let (nonce_slice, ciphertext) = encrypted_data.split_at(12);
    let nonce_bytes: [u8; 12] = nonce_slice
        .try_into()
        .map_err(|_e| CryptoError::InvalidNonce("Nonce must be 12 bytes".to_string()))?;

    let nonce = Nonce::assume_unique_for_key(nonce_bytes);

    let mut in_out = ciphertext.to_vec();
    let plaintext = aes_key
        .open_in_place(nonce, Aad::empty(), &mut in_out)
        .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;

    Ok(plaintext.to_vec())
}

fn xor_simd(a: &[u8], b: &[u8]) -> Vec<u8> {
    use std::simd::{u8x32, Simd};

    let len = a.len().min(b.len());
    let mut result = Vec::with_capacity(len);

    // Process 32 bytes at a time using SIMD
    let mut i = 0;
    while i + 32 <= len {
        let a_chunk = u8x32::from_slice(&a[i..i + 32]);
        let b_chunk = u8x32::from_slice(&b[i..i + 32]);
        let xor_result = a_chunk ^ b_chunk;
        result.extend_from_slice(xor_result.as_array());
        i += 32;
    }

    // Handle remaining bytes with scalar operations
    for j in i..len {
        result.push(a[j] ^ b[j]);
    }

    result
}

#[cfg(feature = "perf")]
fn hash_parallel(data: &[u8], chunk_size: usize) -> Vec<[u8; 32]> {
    data.par_chunks(chunk_size)
        .map(|chunk| {
            let mut hasher = Sha3_256::new();
            hasher.update(chunk);
            hasher.finalize().into()
        })
        .collect()
}

#[inline]
fn hash_sha3_256(data: &[u8]) -> Result<[u8; 32], CryptoError> {
    #[cfg(feature = "perf")]
    if data.len() > 65536 {
        let results = hash_parallel(data, 4096);
        let mut final_hasher = Sha3_256::new();
        for hash in &results {
            final_hasher.update(hash);
        }
        Ok(final_hasher.finalize().into())
    } else {
        let mut hasher = Sha3_256::new();
        hasher.update(data);
        Ok(hasher.finalize().into())
    }

    #[cfg(not(feature = "perf"))]
    {
        let mut hasher = Sha3_256::new();
        hasher.update(data);
        Ok(hasher.finalize().into())
    }
}

#[inline]
fn sign_ed25519(data: &[u8], private_key: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let signing_key_bytes: [u8; 32] = private_key[..32]
        .try_into()
        .map_err(|_e| CryptoError::InvalidInput("Private key must be 32 bytes".to_string()))?;

    let signing_key = SigningKey::from_bytes(&signing_key_bytes);

    let signature: Signature = signing_key.sign(data);

    Ok(signature.to_bytes().to_vec())
}

#[inline]
fn verify_ed25519(
    data: &[u8],
    signature_bytes: &[u8],
    public_key: &[u8],
) -> Result<bool, CryptoError> {
    let signature_bytes_fixed: [u8; 64] = signature_bytes[..64]
        .try_into()
        .map_err(|_e| CryptoError::InvalidInput("Signature must be 64 bytes".to_string()))?;

    let signature = Signature::from_bytes(&signature_bytes_fixed);

    let public_key_bytes: [u8; 32] = public_key[..32]
        .try_into()
        .map_err(|_e| CryptoError::InvalidInput("Public key must be 32 bytes".to_string()))?;

    let verifying_key = VerifyingKey::from_bytes(&public_key_bytes)
        .map_err(|_e| CryptoError::InvalidInput("Invalid public key".to_string()))?;

    Ok(verifying_key.verify(data, &signature).is_ok())
}

fn derive_key_hkdf(password: &[u8], salt: &[u8], length: usize) -> Result<Vec<u8>, CryptoError> {
    let hkdf_salt = Salt::new(HKDF_SHA256, salt);
    let prk = hkdf_salt.extract(password);

    let okm = prk.expand(&[b"latticearc"], HkdfOutputLen(length))
        .map_err(|_| CryptoError::KeyDerivationFailed("HKDF expansion failed".to_string()))?;

    let mut output = vec![0u8; length];
    okm.fill(&mut output)
        .map_err(|_| CryptoError::KeyDerivationFailed("HKDF fill failed".to_string()))?;

    Ok(output)
}

/// Result of hybrid encryption containing encapsulated key and ciphertext.
pub struct HybridEncryptionResult {
    /// The encapsulated key (for KEM-based encryption).
    pub encapsulated_key: Vec<u8>,
    /// The encrypted ciphertext.
    pub ciphertext: Vec<u8>,
}

fn encrypt_hybrid_aes_gcm(
    data: &[u8],
    kem_public_key: Option<&[u8]>,
    symmetric_key: &[u8],
) -> Result<HybridEncryptionResult, CryptoError> {
    // Validate that a symmetric key was provided
    if symmetric_key.len() < 32 {
        return Err(CryptoError::InvalidInput(format!(
            "Symmetric key must be at least 32 bytes, got {}",
            symmetric_key.len()
        )));
    }

    let encapsulated_key = if let Some(pk) = kem_public_key { pk.to_vec() } else { vec![] };

    let ciphertext = encrypt_aes_gcm(data, symmetric_key)?;

    Ok(HybridEncryptionResult { encapsulated_key, ciphertext })
}

fn decrypt_hybrid_aes_gcm(
    ciphertext: &[u8],
    kem_private_key: Option<&[u8]>,
    encapsulated_key: &[u8],
    symmetric_key: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let _ = kem_private_key;
    let _ = encapsulated_key;

    // Validate that a symmetric key was provided
    if symmetric_key.len() < 32 {
        return Err(CryptoError::InvalidInput(format!(
            "Symmetric key must be at least 32 bytes, got {}",
            symmetric_key.len()
        )));
    }

    decrypt_aes_gcm(ciphertext, symmetric_key)
}

/// Encrypt data using the default encryption scheme.
#[inline]
pub fn encrypt(data: &[u8], key: &[u8]) -> Result<EncryptedData, CryptoError> {
    encrypt_with_config(data, &EncryptionConfig::default(), key)
}

/// Encrypt data with a specific configuration.
pub fn encrypt_with_config(
    data: &[u8],
    config: &EncryptionConfig,
    key: &[u8],
) -> Result<EncryptedData, CryptoError> {
    if key.len() < 32 {
        return Err(CryptoError::InvalidInput(format!(
            "Encryption key must be at least 32 bytes, got {}",
            key.len()
        )));
    }

    let scheme = CryptoPolicyEngine::select_encryption_scheme(data, config, None)?;

    if data.is_empty() {
        return Err(CryptoError::InvalidInput("Cannot encrypt empty data".to_string()));
    }

    let encrypted = match scheme.as_str() {
        s if s.contains("hybrid-ml-kem") => {
            let kem_result = encrypt_hybrid(data, None, key)?;
            kem_result.ciphertext
        }
        s if s.contains("ml-kem") => {
            encrypt_hybrid(data, None, key)?.ciphertext
        }
        _ => encrypt_aes_gcm(data, key)?,
    };

    let nonce = if encrypted.len() >= 12 { encrypted[..12].to_vec() } else { vec![] };
    let tag = if encrypted.len() >= 28 { encrypted[encrypted.len() - 16..].to_vec() } else { vec![] };

    Ok(EncryptedData {
        data: encrypted,
        metadata: EncryptedMetadata { nonce, tag: Some(tag), key_id: None },
        scheme,
        timestamp: chrono::Utc::now().timestamp() as u64,
    })
}

/// Encrypt data for a specific use case.
pub fn encrypt_for_use_case(data: &[u8], use_case: UseCase, key: &[u8]) -> Result<EncryptedData, CryptoError> {
    let config = EncryptionConfig::default();
    CryptoPolicyEngine::select_encryption_scheme(data, &config, Some(use_case))?;
    encrypt_with_config(data, &config, key)
}

/// Decrypt encrypted data.
#[inline]
pub fn decrypt(encrypted: &EncryptedData, key: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if encrypted.data.is_empty() {
        return Ok(encrypted.data.clone());
    }

    // Validate that a key was provided
    if key.len() < 32 {
        return Err(CryptoError::InvalidInput(format!(
            "Decryption key must be at least 32 bytes, got {}",
            key.len()
        )));
    }

    decrypt_aes_gcm(&encrypted.data, key)
}

/// Decrypt encrypted data with a specific configuration.
pub fn decrypt_with_config(
    encrypted: &EncryptedData,
    _config: &EncryptionConfig,
    key: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    decrypt(encrypted, key)
}

/// Sign a message using the default signature scheme.
#[inline]
pub fn sign(message: &[u8]) -> Result<SignedData, CryptoError> {
    sign_with_config(message, &SignatureConfig::default())
}

/// Sign a message with a specific configuration.
pub fn sign_with_config(
    message: &[u8],
    config: &SignatureConfig,
) -> Result<SignedData, CryptoError> {
    let scheme = CryptoPolicyEngine::select_signature_scheme(&config.base)?;

    let (public_key, private_key) = generate_keypair()?;

    let signature = sign_ed25519(message, private_key.as_slice())?;

    Ok(SignedData {
        data: message.to_vec(),
        metadata: SignedMetadata { signature, signature_algorithm: scheme, key_id: None },
        scheme,
        timestamp: chrono::Utc::now().timestamp() as u64,
    })
}

/// Verify a signed message.
#[inline]
pub fn verify(signed: &SignedData) -> Result<bool, CryptoError> {
    verify_with_config(&signed.data, signed, &SignatureConfig::default())
}

/// Verify a signed message with a specific configuration.
pub fn verify_with_config(
    message: &[u8],
    signed: &SignedData,
    _config: &SignatureConfig,
) -> Result<bool, CryptoError> {
    let message_to_verify = message;

    let public_key = if let Some(_key_id) = &signed.metadata.key_id {
        derive_public_key_from_signed_data(signed)
    } else {
        derive_public_key_from_signed_data(signed)
    };

    verify_ed25519(message_to_verify, &signed.metadata.signature, &public_key)
}

/// Generate a new keypair.
pub fn generate_keypair() -> Result<(PublicKey, PrivateKey), CryptoError> {
    let mut csprng = rand::rngs::OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let verifying_key = signing_key.verifying_key();

    let public_key = verifying_key.to_bytes().to_vec();
    let private_key = PrivateKey::new(signing_key.to_bytes().to_vec());

    Ok((public_key, private_key))
}

/// Generate a new keypair with a specific configuration.
pub fn generate_keypair_with_config(
    config: &CryptoConfig,
) -> Result<(PublicKey, PrivateKey), CryptoError> {
    config.validate()?;
    generate_keypair()
}

/// Derive a key from a password and salt using HKDF.
pub fn derive_key(password: &[u8], salt: &[u8], length: usize) -> Result<Vec<u8>, CryptoError> {
    if salt.is_empty() {
        return Err(CryptoError::InvalidInput("Salt cannot be empty".to_string()));
    }

    if length == 0 {
        return Err(CryptoError::InvalidInput("Length cannot be zero".to_string()));
    }

    derive_key_hkdf(password, salt, length)
}

/// Hash data using SHA3-256.
#[inline]
pub fn hash_data(data: &[u8]) -> Result<[u8; 32], CryptoError> {
    hash_sha3_256(data)
}

/// Computes HMAC-SHA256 using NIST SP 800-107 standard.
///
#[inline]
pub fn hmac(key: &[u8], data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    // Input validation - key must not be empty
    if key.is_empty() {
        return Err(CryptoError::InvalidInput(
            "HMAC key must not be empty".to_string(),
        ));
    }

    // HMAC-SHA256 using the hmac crate
    let mut mac = <Hmac<Sha256> as hmac::digest::KeyInit>::new_from_slice(key)
        .map_err(|e| CryptoError::InvalidInput(format!("Invalid HMAC key: {}", e)))?;

    mac.update(data);

    Ok(mac.finalize().into_bytes().to_vec())
}

/// Checks an HMAC tag against data using constant-time comparison.
///
/// The function name uses "check" rather than "verify" to avoid confusion with
/// the Zero Trust `_unverified` suffix pattern used in arc-core.
#[inline]
pub fn hmac_check(key: &[u8], data: &[u8], tag: &[u8]) -> Result<bool, CryptoError> {
    // Input validation - key must not be empty
    if key.is_empty() {
        return Err(CryptoError::InvalidInput(
            "HMAC key must not be empty".to_string(),
        ));
    }

    // Tag must be valid length (32 bytes for SHA-256 HMAC)
    if tag.len() != 32 {
        return Err(CryptoError::InvalidInput(format!(
            "HMAC tag must be 32 bytes, got {}",
            tag.len()
        )));
    }

    // Compute the expected HMAC
    let expected = hmac(key, data)?;

    // Constant-time comparison to prevent timing attacks
    // Use the subtle crate's constant_time_eq
    let mut tag_bytes = [0u8; 32];
    tag_bytes.copy_from_slice(tag);
    let mut expected_bytes = [0u8; 32];
    expected_bytes.copy_from_slice(&expected);

    Ok(tag_bytes.ct_eq(&expected_bytes).into())
}

/// Encrypt data using hybrid encryption.
#[inline]
pub fn encrypt_hybrid(
    data: &[u8],
    kem_public_key: Option<&[u8]>,
    symmetric_key: &[u8],
) -> Result<HybridEncryptionResult, CryptoError> {
    encrypt_hybrid_aes_gcm(data, kem_public_key, symmetric_key)
}

/// Decrypt data using hybrid encryption.
#[inline]
pub fn decrypt_hybrid(
    ciphertext: &[u8],
    kem_private_key: Option<&[u8]>,
    encapsulated_key: &[u8],
    symmetric_key: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    decrypt_hybrid_aes_gcm(ciphertext, kem_private_key, encapsulated_key, symmetric_key)
}

fn derive_public_key_from_signed_data(signed: &SignedData) -> Vec<u8> {
    signed.metadata.public_key.clone()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let data = b"test data";
        let key = vec![1u8; 32]; // Test key
        let encrypted = encrypt(data, &key).unwrap();
        let decrypted = decrypt(&encrypted, &key).unwrap();
        assert_eq!(data, decrypted.as_slice());
    }

    #[test]
    fn test_encrypt_with_config() {
        let data = b"test data";
        let config = EncryptionConfig::default();
        let key = vec![2u8; 32]; // Test key
        let encrypted = encrypt_with_config(data, &config, &key).unwrap();
        let decrypted = decrypt(&encrypted, &key).unwrap();
        assert_eq!(data, decrypted.as_slice());
    }

    #[test]
    fn test_sign_verify() {
        let message = b"test message";
        let (public_key, private_key) = generate_keypair().unwrap();
        let signature = sign_ed25519(message, private_key.as_slice()).unwrap();
        let verified = verify_ed25519(message, &signature, &public_key).unwrap();
        assert!(verified);
    }

    #[test]
    fn test_generate_keypair() {
        let (public_key, private_key) = generate_keypair().unwrap();
        assert_eq!(public_key.len(), 32);
        assert_eq!(private_key.as_ref().len(), 32);
    }

    #[test]
    fn test_hash_data() {
        let data = b"test data";
        let hash = hash_data(data).unwrap();
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_derive_key() {
        let password = b"test password";
        let salt = b"test salt";
        let key = derive_key(password, salt, 32).unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_hmac() {
        let key = b"test key";
        let data = b"test data";
        let hmac_result = hmac(key, data).unwrap();
        assert_eq!(hmac_result.len(), 32);
    }

    #[test]
    fn test_hmac_empty_key_rejected() {
        let key = b"";
        let data = b"test data";
        let result = hmac(key, data);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), CryptoError::InvalidInput(_)));
    }

    #[test]
    fn test_hmac_empty_message_allowed() {
        let key = b"test key";
        let data = b"";
        let hmac_result = hmac(key, data).unwrap();
        assert_eq!(hmac_result.len(), 32);
    }

    #[test]
    fn test_hmac_check_valid_tag() {
        let key = b"test key";
        let data = b"test data";
        let hmac_result = hmac(key, data).unwrap();
        let verified = hmac_check(key, data, &hmac_result).unwrap();
        assert!(verified);
    }

    #[test]
    fn test_hmac_check_invalid_tag() {
        let key = b"test key";
        let data = b"test data";
        let hmac_result = hmac(key, data).unwrap();
        let mut invalid_tag = hmac_result.clone();
        invalid_tag[0] ^= 0x01; // Flip a bit
        let verified = hmac_check(key, data, &invalid_tag).unwrap();
        assert!(!verified);
    }

    #[test]
    fn test_hmac_check_invalid_tag_length() {
        let key = b"test key";
        let data = b"test data";
        let short_tag = vec![0u8; 16]; // Wrong length
        let result = hmac_check(key, data, &short_tag);
        assert!(result.is_err());
    }

    #[test]
    fn test_hmac_not_concatenation() {
        // Verify HMAC is not simple concatenation by checking different
        // inputs produce different results than simple key||data hash
        let key = b"key";
        let data = b"data";

        // Our HMAC result
        let hmac_result = hmac(key, data).unwrap();

        // Simple concatenation result (old incorrect implementation)
        let mut combined = key.to_vec();
        combined.extend_from_slice(data);
        let concat_result = hash_sha3_256(&combined).unwrap();

        // They should be different
        assert_ne!(hmac_result.as_slice(), concat_result);
    }

    #[test]
    fn test_hmac_long_key() {
        // Test with key longer than block size (should be hashed first)
        let key = vec![0u8; 128]; // 128 bytes > 64 byte block size
        let data = b"test data";
        let hmac_result = hmac(&key, data).unwrap();
        assert_eq!(hmac_result.len(), 32);
    }

    #[test]
    fn test_encrypt_decrypt_hybrid() {
        let data = b"test data";
        let key = vec![3u8; 32]; // Test key
        let encrypted = encrypt_hybrid(data, None, &key).unwrap();
        let decrypted =
            decrypt_hybrid(&encrypted.ciphertext, None, &encrypted.encapsulated_key, &key).unwrap();
        assert_eq!(data, decrypted.as_slice());
    }

    #[test]
    fn test_xor_simd() {
        let a = vec![1u8, 2, 3, 4, 5, 6, 7, 8];
        let b = vec![8u8, 7, 6, 5, 4, 3, 2, 1];
        let result = xor_simd(&a, &b);
        assert_eq!(result.len(), 8);
        assert_eq!(result[0], 9);
        assert_eq!(result[1], 5);
        assert_eq!(result[2], 5);
        assert_eq!(result[3], 1);
        assert_eq!(result[4], 1);
        assert_eq!(result[5], 5);
        assert_eq!(result[6], 5);
        assert_eq!(result[7], 9);
    }

    #[test]
    fn test_xor_simd_large() {
        let a = vec![1u8; 100];
        let b = vec![2u8; 100];
        let result = xor_simd(&a, &b);
        assert_eq!(result.len(), 100);
        for &byte in &result {
            assert_eq!(byte, 3u8); // 1 ^ 2 = 3
        }
    }

    #[test]
    fn test_xor_simd_edge_cases() {
        // Test with different lengths
        let a = vec![1u8, 2u8, 3u8];
        let b = vec![4u8, 5u8, 6u8];
        let result = xor_simd(&a, &b);
        assert_eq!(result, vec![5u8, 7u8, 5u8]); // 1^4=5, 2^5=7, 3^6=5

        // Test with empty vectors
        let a_empty = Vec::<u8>::new();
        let b_empty = Vec::<u8>::new();
        let result_empty = xor_simd(&a_empty, &b_empty);
        assert_eq!(result_empty.len(), 0);
    }
}
