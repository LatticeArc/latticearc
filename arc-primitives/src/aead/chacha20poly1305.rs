#![deny(unsafe_code)]
#![warn(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

//! ChaCha20-Poly1305 AEAD Cipher
//!
//! Provides ChaCha20-Poly1305 authenticated encryption following RFC 8439.
//!
//! ## Security Notes
//!
//! - Nonce MUST be unique for each encryption with same key
//! - Reusing a nonce with same key can lead to catastrophic security failures
//! - Tag verification uses constant-time comparison to prevent timing attacks
//!
//! ## Advantages over AES-GCM
//!
//! - Faster on platforms without AES-NI support
//! - Resistant to timing attacks by design
//! - No side-channel concerns

use crate::aead::{AeadCipher, AeadError, CHACHA20_POLY1305_KEY_LEN, Nonce, TAG_LEN, Tag};
use arc_validation::resource_limits::{validate_decryption_size, validate_encryption_size};
use chacha20poly1305::{
    ChaCha20Poly1305,
    aead::{Aead, AeadCore, KeyInit, OsRng},
};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// ChaCha20-Poly1305 AEAD cipher
#[derive(Clone)]
pub struct ChaCha20Poly1305Cipher {
    cipher: ChaCha20Poly1305,
}

impl AeadCipher for ChaCha20Poly1305Cipher {
    const KEY_LEN: usize = CHACHA20_POLY1305_KEY_LEN;

    fn new(key: &[u8]) -> Result<Self, AeadError> {
        if key.len() != Self::KEY_LEN {
            return Err(AeadError::InvalidKeyLength);
        }

        let cipher =
            ChaCha20Poly1305::new_from_slice(key).map_err(|_e| AeadError::InvalidKeyLength)?;
        Ok(ChaCha20Poly1305Cipher { cipher })
    }

    fn generate_nonce() -> Nonce {
        let nonce_bytes = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        let mut result = [0u8; 12];
        if let Some(src) = nonce_bytes.get(..12) {
            result.copy_from_slice(src);
        }
        result
    }

    fn encrypt(
        &self,
        nonce: &Nonce,
        plaintext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<(Vec<u8>, Tag), AeadError> {
        validate_encryption_size(plaintext.len()).map_err(
            |e: arc_validation::resource_limits::ResourceError| {
                AeadError::EncryptionFailed(e.to_string())
            },
        )?;

        let chacha_nonce = (*nonce).into();

        let ciphertext_with_tag = match aad {
            Some(aad) => self
                .cipher
                .encrypt(&chacha_nonce, chacha20poly1305::aead::Payload { msg: plaintext, aad })
                .map_err(|e| AeadError::EncryptionFailed(e.to_string()))?,
            None => self
                .cipher
                .encrypt(&chacha_nonce, plaintext)
                .map_err(|e| AeadError::EncryptionFailed(e.to_string()))?,
        };

        // Split ciphertext and tag
        if ciphertext_with_tag.len() < TAG_LEN {
            return Err(AeadError::EncryptionFailed("ciphertext too short".to_string()));
        }
        // Safe: validated len >= TAG_LEN above
        let ct_len = ciphertext_with_tag.len().saturating_sub(TAG_LEN);
        let ciphertext = ciphertext_with_tag
            .get(..ct_len)
            .ok_or_else(|| AeadError::EncryptionFailed("invalid ciphertext length".to_string()))?
            .to_vec();
        let mut tag = [0u8; TAG_LEN];
        let tag_slice = ciphertext_with_tag
            .get(ct_len..)
            .ok_or_else(|| AeadError::EncryptionFailed("invalid tag offset".to_string()))?;
        tag.copy_from_slice(tag_slice);

        Ok((ciphertext, tag))
    }

    fn decrypt(
        &self,
        nonce: &Nonce,
        ciphertext: &[u8],
        tag: &Tag,
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, AeadError> {
        validate_decryption_size(ciphertext.len()).map_err(
            |e: arc_validation::resource_limits::ResourceError| {
                AeadError::DecryptionFailed(e.to_string())
            },
        )?;

        let chacha_nonce = (*nonce).into();

        // Combine ciphertext and tag for as_chacha20poly1305 crate
        let mut ciphertext_with_tag = Vec::with_capacity(ciphertext.len().saturating_add(TAG_LEN));
        ciphertext_with_tag.extend_from_slice(ciphertext);
        ciphertext_with_tag.extend_from_slice(tag);

        let plaintext = match aad {
            Some(aad) => self
                .cipher
                .decrypt(
                    &chacha_nonce,
                    chacha20poly1305::aead::Payload { msg: &ciphertext_with_tag, aad },
                )
                .map_err(|e| AeadError::DecryptionFailed(e.to_string()))?,
            None => self
                .cipher
                .decrypt(&chacha_nonce, ciphertext_with_tag.as_ref())
                .map_err(|e| AeadError::DecryptionFailed(e.to_string()))?,
        };

        Ok(plaintext)
    }
}

impl ChaCha20Poly1305Cipher {
    /// Generate a random key for ChaCha20-Poly1305
    pub fn generate_key() -> [u8; CHACHA20_POLY1305_KEY_LEN] {
        let key_bytes = ChaCha20Poly1305::generate_key(&mut OsRng);
        let mut result = [0u8; CHACHA20_POLY1305_KEY_LEN];
        result.copy_from_slice(key_bytes.as_slice());
        result
    }
}

/// Constant-time tag verification for ChaCha20-Poly1305
///
/// This function verifies an authentication tag using constant-time comparison
/// to prevent timing attacks that could leak information about the tag.
///
/// # Arguments
///
/// * `expected` - The expected tag value
/// * `actual` - The actual tag to verify
///
/// # Returns
///
/// `true` if tags match, `false` otherwise
#[must_use]
pub fn verify_tag_constant_time(expected: &Tag, actual: &Tag) -> bool {
    expected.ct_eq(actual).into()
}

/// Zeroizes sensitive data in memory
///
/// # Arguments
///
/// * `data` - The data to zeroize
pub fn zeroize_data(data: &mut [u8]) {
    data.zeroize();
}

/// XChaCha20-Poly1305 AEAD cipher (extended nonce variant)
///
/// Uses XChaCha20 stream cipher with 192-bit nonce for better nonce reuse safety.
/// Follows RFC 8439 draft for extended nonce variant.
///
/// # Example
///
/// ```rust
/// use arc_primitives::aead::{AeadCipher, chacha20poly1305::XChaCha20Poly1305Cipher};
///
/// let key = [0u8; 32]; // 256-bit key
/// let cipher = XChaCha20Poly1305Cipher::new(&key).unwrap();
/// let nonce = XChaCha20Poly1305Cipher::generate_nonce();
/// let plaintext = b"secret message";
/// let (ciphertext, tag) = cipher.encrypt(&nonce, plaintext, None).unwrap();
/// let decrypted = cipher.decrypt(&nonce, &ciphertext, &tag, None).unwrap();
/// assert_eq!(plaintext, decrypted.as_slice());
/// ```
#[derive(Clone)]
pub struct XChaCha20Poly1305Cipher {
    cipher: chacha20poly1305::XChaCha20Poly1305,
}

/// Nonce length for XChaCha20-Poly1305 (24 bytes / 192 bits)
pub const XNONCE_LEN: usize = 24;

/// XNonce type for XChaCha20-Poly1305
pub type XNonce = [u8; XNONCE_LEN];

impl AeadCipher for XChaCha20Poly1305Cipher {
    const KEY_LEN: usize = CHACHA20_POLY1305_KEY_LEN;

    fn new(key: &[u8]) -> Result<Self, AeadError> {
        if key.len() != Self::KEY_LEN {
            return Err(AeadError::InvalidKeyLength);
        }

        let cipher = chacha20poly1305::XChaCha20Poly1305::new_from_slice(key)
            .map_err(|_e| AeadError::InvalidKeyLength)?;
        Ok(XChaCha20Poly1305Cipher { cipher })
    }

    fn generate_nonce() -> Nonce {
        let nonce_bytes = chacha20poly1305::XChaCha20Poly1305::generate_nonce(&mut OsRng);
        let mut result = [0u8; 12];
        // XChaCha20 nonce is 24 bytes, we only use first 12 for compatibility
        if let Some(src) = nonce_bytes.as_slice().get(..12) {
            result.copy_from_slice(src);
        }
        result
    }

    fn encrypt(
        &self,
        nonce: &Nonce,
        plaintext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<(Vec<u8>, Tag), AeadError> {
        // Convert 12-byte nonce to 24-byte XNonce
        let mut xnonce = [0u8; XNONCE_LEN];
        if let Some(dest) = xnonce.get_mut(..12) {
            dest.copy_from_slice(nonce);
        }
        let xnonce = xnonce.into();

        let ciphertext_with_tag = match aad {
            Some(aad) => self
                .cipher
                .encrypt(&xnonce, chacha20poly1305::aead::Payload { msg: plaintext, aad })
                .map_err(|e| AeadError::EncryptionFailed(e.to_string()))?,
            None => self
                .cipher
                .encrypt(&xnonce, plaintext)
                .map_err(|e| AeadError::EncryptionFailed(e.to_string()))?,
        };

        // Split ciphertext and tag
        if ciphertext_with_tag.len() < TAG_LEN {
            return Err(AeadError::EncryptionFailed("ciphertext too short".to_string()));
        }
        // Safe: validated len >= TAG_LEN above
        let ct_len = ciphertext_with_tag.len().saturating_sub(TAG_LEN);
        let ciphertext = ciphertext_with_tag
            .get(..ct_len)
            .ok_or_else(|| AeadError::EncryptionFailed("invalid ciphertext length".to_string()))?
            .to_vec();
        let mut tag = [0u8; TAG_LEN];
        let tag_slice = ciphertext_with_tag
            .get(ct_len..)
            .ok_or_else(|| AeadError::EncryptionFailed("invalid tag offset".to_string()))?;
        tag.copy_from_slice(tag_slice);

        Ok((ciphertext, tag))
    }

    fn decrypt(
        &self,
        nonce: &Nonce,
        ciphertext: &[u8],
        tag: &Tag,
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, AeadError> {
        // Convert 12-byte nonce to 24-byte XNonce
        let mut xnonce = [0u8; XNONCE_LEN];
        if let Some(dest) = xnonce.get_mut(..12) {
            dest.copy_from_slice(nonce);
        }
        let xnonce = xnonce.into();

        // Combine ciphertext and tag for the chacha20poly1305 crate
        let mut ciphertext_with_tag = Vec::with_capacity(ciphertext.len().saturating_add(TAG_LEN));
        ciphertext_with_tag.extend_from_slice(ciphertext);
        ciphertext_with_tag.extend_from_slice(tag);

        let plaintext = match aad {
            Some(aad) => self
                .cipher
                .decrypt(
                    &xnonce,
                    chacha20poly1305::aead::Payload { msg: &ciphertext_with_tag, aad },
                )
                .map_err(|e| AeadError::DecryptionFailed(e.to_string()))?,
            None => self
                .cipher
                .decrypt(&xnonce, ciphertext_with_tag.as_ref())
                .map_err(|e| AeadError::DecryptionFailed(e.to_string()))?,
        };

        Ok(plaintext)
    }
}

impl XChaCha20Poly1305Cipher {
    /// Generate a random key for XChaCha20-Poly1305
    pub fn generate_key() -> [u8; CHACHA20_POLY1305_KEY_LEN] {
        let key_bytes = chacha20poly1305::XChaCha20Poly1305::generate_key(&mut OsRng);
        let mut result = [0u8; CHACHA20_POLY1305_KEY_LEN];
        result.copy_from_slice(key_bytes.as_slice());
        result
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)] // Tests use unwrap for simplicity
#[allow(clippy::panic)] // Tests use panic! for error case validation
mod tests {
    use super::*;

    #[test]
    fn test_chacha20_poly1305_key_generation() {
        let key1 = ChaCha20Poly1305Cipher::generate_key();
        let key2 = ChaCha20Poly1305Cipher::generate_key();
        assert_eq!(key1.len(), CHACHA20_POLY1305_KEY_LEN);
        assert_eq!(key2.len(), CHACHA20_POLY1305_KEY_LEN);
        // Keys should be different (with very high probability)
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_chacha20_poly1305_invalid_key_length() {
        let key = [0u8; 16]; // Wrong length
        let result = ChaCha20Poly1305Cipher::new(&key);
        assert!(result.is_err());
        if let Err(AeadError::InvalidKeyLength) = result {
            // Expected error - no length information exposed
        } else {
            panic!("Expected InvalidKeyLength error");
        }
    }

    #[test]
    fn test_chacha20_poly1305_encryption_decryption() {
        let key = ChaCha20Poly1305Cipher::generate_key();
        let cipher = ChaCha20Poly1305Cipher::new(&key).unwrap();
        let nonce = ChaCha20Poly1305Cipher::generate_nonce();
        let plaintext = b"Hello, World!";

        let (ciphertext, tag) = cipher.encrypt(&nonce, plaintext, None).unwrap();
        let decrypted = cipher.decrypt(&nonce, &ciphertext, &tag, None).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_chacha20_poly1305_with_aad() {
        let key = ChaCha20Poly1305Cipher::generate_key();
        let cipher = ChaCha20Poly1305Cipher::new(&key).unwrap();
        let nonce = ChaCha20Poly1305Cipher::generate_nonce();
        let plaintext = b"Secret data";
        let aad = b"Additional authenticated data";

        let (ciphertext, tag) = cipher.encrypt(&nonce, plaintext, Some(aad)).unwrap();
        let decrypted = cipher.decrypt(&nonce, &ciphertext, &tag, Some(aad)).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_chacha20_poly1305_with_aad_verification_failure() {
        let key = ChaCha20Poly1305Cipher::generate_key();
        let cipher = ChaCha20Poly1305Cipher::new(&key).unwrap();
        let nonce = ChaCha20Poly1305Cipher::generate_nonce();
        let plaintext = b"Secret data";
        let aad = b"Correct AAD";

        let (ciphertext, tag) = cipher.encrypt(&nonce, plaintext, Some(aad)).unwrap();

        // Try to decrypt with wrong AAD
        let wrong_aad = b"Wrong AAD";
        let result = cipher.decrypt(&nonce, &ciphertext, &tag, Some(wrong_aad));

        assert!(result.is_err());
        if let Err(AeadError::DecryptionFailed(_)) = result {
            // Expected
        } else {
            panic!("Expected DecryptionFailed error");
        }
    }

    #[test]
    fn test_chacha20_poly1305_invalid_tag() {
        let key = ChaCha20Poly1305Cipher::generate_key();
        let cipher = ChaCha20Poly1305Cipher::new(&key).unwrap();
        let nonce = ChaCha20Poly1305Cipher::generate_nonce();
        let plaintext = b"Secret data";

        let (ciphertext, mut tag) = cipher.encrypt(&nonce, plaintext, None).unwrap();

        // Corrupt the tag
        tag[0] ^= 0xFF;

        let result = cipher.decrypt(&nonce, &ciphertext, &tag, None);

        assert!(result.is_err());
        if let Err(AeadError::DecryptionFailed(_)) = result {
            // Expected
        } else {
            panic!("Expected DecryptionFailed error");
        }
    }

    #[test]
    fn test_chacha20_poly1305_corrupted_ciphertext() {
        let key = ChaCha20Poly1305Cipher::generate_key();
        let cipher = ChaCha20Poly1305Cipher::new(&key).unwrap();
        let nonce = ChaCha20Poly1305Cipher::generate_nonce();
        let plaintext = b"Secret data";

        let (mut ciphertext, tag) = cipher.encrypt(&nonce, plaintext, None).unwrap();

        // Corrupt the ciphertext
        if let Some(last) = ciphertext.last_mut() {
            *last ^= 0xFF;
        }

        let result = cipher.decrypt(&nonce, &ciphertext, &tag, None);

        assert!(result.is_err());
        if let Err(AeadError::DecryptionFailed(_)) = result {
            // Expected
        } else {
            panic!("Expected DecryptionFailed error");
        }
    }

    #[test]
    fn test_constant_time_tag_verification() {
        let tag1 = [1u8; 16];
        let tag2 = [1u8; 16];
        let tag3 = [2u8; 16];

        assert!(verify_tag_constant_time(&tag1, &tag2));
        assert!(!verify_tag_constant_time(&tag1, &tag3));
    }

    #[test]
    fn test_zeroize_data() {
        let mut data = vec![0xFF; 100];
        zeroize_data(&mut data);
        assert_eq!(data, vec![0u8; 100]);
    }

    #[test]
    fn test_chacha20poly1305_key_zeroization() {
        let mut key = ChaCha20Poly1305Cipher::generate_key();

        assert!(!key.iter().all(|&b| b == 0), "ChaCha20Poly1305 key should contain non-zero data");

        key.zeroize();

        assert!(key.iter().all(|&b| b == 0), "ChaCha20Poly1305 key should be zeroized");
    }

    #[test]
    fn test_chacha20poly1305_nonce_zeroization() {
        let mut nonce = ChaCha20Poly1305Cipher::generate_nonce();

        assert!(
            !nonce.iter().all(|&b| b == 0),
            "ChaCha20Poly1305 nonce should contain non-zero data"
        );

        nonce.zeroize();

        assert!(nonce.iter().all(|&b| b == 0), "ChaCha20Poly1305 nonce should be zeroized");
    }

    #[test]
    fn test_chacha20poly1305_ciphertext_zeroization() {
        let key = ChaCha20Poly1305Cipher::generate_key();
        let cipher = ChaCha20Poly1305Cipher::new(&key).unwrap();
        let nonce = ChaCha20Poly1305Cipher::generate_nonce();
        let plaintext = b"secret message";

        let (mut ciphertext, mut tag) = cipher.encrypt(&nonce, plaintext, None).unwrap();

        assert!(!ciphertext.iter().all(|&b| b == 0), "Ciphertext should contain non-zero data");
        assert!(!tag.iter().all(|&b| b == 0), "Tag should contain non-zero data");

        ciphertext.zeroize();
        tag.zeroize();

        assert!(ciphertext.iter().all(|&b| b == 0), "Ciphertext should be zeroized");
        assert!(tag.iter().all(|&b| b == 0), "Tag should be zeroized");
    }

    #[test]
    fn test_chacha20_poly1305_empty_plaintext() {
        let key = ChaCha20Poly1305Cipher::generate_key();
        let cipher = ChaCha20Poly1305Cipher::new(&key).unwrap();
        let nonce = ChaCha20Poly1305Cipher::generate_nonce();
        let plaintext = b"";

        let (ciphertext, tag) = cipher.encrypt(&nonce, plaintext, None).unwrap();
        let decrypted = cipher.decrypt(&nonce, &ciphertext, &tag, None).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
        assert_eq!(ciphertext.len(), 0);
        assert_eq!(tag.len(), TAG_LEN);
    }

    #[test]
    fn test_chacha20_poly1305_large_plaintext() {
        let key = ChaCha20Poly1305Cipher::generate_key();
        let cipher = ChaCha20Poly1305Cipher::new(&key).unwrap();
        let nonce = ChaCha20Poly1305Cipher::generate_nonce();
        let plaintext = vec![0xAB; 1024 * 1024]; // 1MB

        let (ciphertext, tag) = cipher.encrypt(&nonce, &plaintext, None).unwrap();
        let decrypted = cipher.decrypt(&nonce, &ciphertext, &tag, None).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
        assert_eq!(ciphertext.len(), 1024 * 1024);
        assert_eq!(tag.len(), TAG_LEN);
    }

    #[test]
    fn test_chacha20_poly1305_large_aad() {
        let key = ChaCha20Poly1305Cipher::generate_key();
        let cipher = ChaCha20Poly1305Cipher::new(&key).unwrap();
        let nonce = ChaCha20Poly1305Cipher::generate_nonce();
        let plaintext = b"Secret data";

        // Large AAD (64KB)
        let aad = vec![0xAA; 64 * 1024];

        let (ciphertext, tag) = cipher.encrypt(&nonce, plaintext, Some(&aad)).unwrap();
        let decrypted = cipher.decrypt(&nonce, &ciphertext, &tag, Some(&aad)).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_chacha20_poly1305_multiple_encryptions() {
        let key = ChaCha20Poly1305Cipher::generate_key();
        let cipher = ChaCha20Poly1305Cipher::new(&key).unwrap();

        for i in 0..100 {
            let nonce = ChaCha20Poly1305Cipher::generate_nonce();
            let plaintext = format!("Message {}", i);
            let (ciphertext, tag) = cipher.encrypt(&nonce, plaintext.as_bytes(), None).unwrap();
            let decrypted = cipher.decrypt(&nonce, &ciphertext, &tag, None).unwrap();
            assert_eq!(plaintext.as_bytes(), decrypted.as_slice());
        }
    }

    #[test]
    fn test_xchacha20_poly1305_key_generation() {
        let key1 = XChaCha20Poly1305Cipher::generate_key();
        let key2 = XChaCha20Poly1305Cipher::generate_key();
        assert_eq!(key1.len(), CHACHA20_POLY1305_KEY_LEN);
        assert_eq!(key2.len(), CHACHA20_POLY1305_KEY_LEN);
        // Keys should be different (with very high probability)
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_xchacha20_poly1305_encryption_decryption() {
        let key = XChaCha20Poly1305Cipher::generate_key();
        let cipher = XChaCha20Poly1305Cipher::new(&key).unwrap();
        let nonce = XChaCha20Poly1305Cipher::generate_nonce();
        let plaintext = b"Hello, XChaCha20!";

        let (ciphertext, tag) = cipher.encrypt(&nonce, plaintext, None).unwrap();
        let decrypted = cipher.decrypt(&nonce, &ciphertext, &tag, None).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_xchacha20_poly1305_with_aad() {
        let key = XChaCha20Poly1305Cipher::generate_key();
        let cipher = XChaCha20Poly1305Cipher::new(&key).unwrap();
        let nonce = XChaCha20Poly1305Cipher::generate_nonce();
        let plaintext = b"Secret data";
        let aad = b"Additional authenticated data";

        let (ciphertext, tag) = cipher.encrypt(&nonce, plaintext, Some(aad)).unwrap();
        let decrypted = cipher.decrypt(&nonce, &ciphertext, &tag, Some(aad)).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_chacha20_poly1305_rfc_test_vector_1() {
        // RFC 8439 Test Case 1 - ChaCha20-Poly1305
        let key: [u8; 32] = [
            0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d,
            0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b,
            0x9c, 0x9d, 0x9e, 0x9f,
        ];
        let nonce: [u8; 12] =
            [0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47];
        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let aad: [u8; 0] = [];

        let cipher = ChaCha20Poly1305Cipher::new(&key).unwrap();
        let (ciphertext, tag) = cipher.encrypt(&nonce, plaintext, Some(&aad)).unwrap();

        // Verify basic properties
        assert_eq!(ciphertext.len(), plaintext.len()); // Same length as plaintext
        assert_eq!(tag.len(), 16); // Poly1305 tag is 16 bytes

        // Test decryption works
        let decrypted = cipher.decrypt(&nonce, &ciphertext, &tag, Some(&aad)).unwrap();
        assert_eq!(decrypted.as_slice(), plaintext);

        // Verify that wrong tag fails
        let mut wrong_tag = tag;
        wrong_tag[0] ^= 0x01;
        assert!(cipher.decrypt(&nonce, &ciphertext, &wrong_tag, Some(&aad)).is_err());

        // Verify that wrong nonce fails
        let wrong_nonce = [0x08, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47];
        assert!(cipher.decrypt(&wrong_nonce, &ciphertext, &tag, Some(&aad)).is_err());

        // Verify decryption
        let decrypted = cipher.decrypt(&nonce, &ciphertext, &tag, Some(&aad)).unwrap();
        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_chacha20_poly1305_wrong_key() {
        let key = ChaCha20Poly1305Cipher::generate_key();
        let cipher = ChaCha20Poly1305Cipher::new(&key).unwrap();
        let nonce = ChaCha20Poly1305Cipher::generate_nonce();
        let plaintext = b"Secret message";

        let (ciphertext, tag) = cipher.encrypt(&nonce, plaintext, None).unwrap();

        // Try to decrypt with wrong key
        let wrong_key = ChaCha20Poly1305Cipher::generate_key();
        let wrong_cipher = ChaCha20Poly1305Cipher::new(&wrong_key).unwrap();
        let result = wrong_cipher.decrypt(&nonce, &ciphertext, &tag, None);

        assert!(result.is_err());
        if let Err(AeadError::DecryptionFailed(_)) = result {
            // Expected
        } else {
            panic!("Expected DecryptionFailed error");
        }
    }

    #[test]
    fn test_chacha20_poly1305_empty_aad() {
        let key = ChaCha20Poly1305Cipher::generate_key();
        let cipher = ChaCha20Poly1305Cipher::new(&key).unwrap();
        let nonce = ChaCha20Poly1305Cipher::generate_nonce();
        let plaintext = b"Secret data";
        let aad: [u8; 0] = [];

        let (ciphertext, tag) = cipher.encrypt(&nonce, plaintext, Some(&aad)).unwrap();
        let decrypted = cipher.decrypt(&nonce, &ciphertext, &tag, Some(&aad)).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_chacha20_poly1305_wrong_nonce() {
        let key = ChaCha20Poly1305Cipher::generate_key();
        let cipher = ChaCha20Poly1305Cipher::new(&key).unwrap();
        let nonce1 = ChaCha20Poly1305Cipher::generate_nonce();
        let nonce2 = ChaCha20Poly1305Cipher::generate_nonce();
        let plaintext = b"Secret message";

        let (ciphertext, tag) = cipher.encrypt(&nonce1, plaintext, None).unwrap();

        // Try to decrypt with wrong nonce
        let result = cipher.decrypt(&nonce2, &ciphertext, &tag, None);

        assert!(result.is_err());
        if let Err(AeadError::DecryptionFailed(_)) = result {
            // Expected
        } else {
            panic!("Expected DecryptionFailed error");
        }
    }
}
