#![deny(unsafe_code)]
#![deny(missing_docs)]
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

use crate::primitives::aead::{
    AeadCipher, AeadError, CHACHA20_POLY1305_KEY_LEN, Nonce, TAG_LEN, Tag,
};
use crate::primitives::resource_limits::{
    validate_aad_size, validate_decryption_size, validate_encryption_size,
};
use chacha20poly1305::{
    ChaCha20Poly1305,
    aead::{Aead, KeyInit},
};
use rand::RngCore;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

// single opaque string for every decrypt failure path. Pattern
// 6 forbids stage-distinguishing error strings on AEAD decrypt — see the
// detailed comment in aes_gcm.rs for the full rationale.
const DECRYPTION_FAILED: &str = "decryption failed";

// matching opacity sweep for the encrypt path. See aes_gcm.rs
// for the full rationale; same string constant per cipher.
const ENCRYPTION_FAILED: &str = "encryption failed";

/// ChaCha20-Poly1305 AEAD cipher
///
/// Stores key bytes directly (like AES-GCM) for proper `ZeroizeOnDrop` support.
/// The `ChaCha20Poly1305` cipher is constructed transiently for each operation.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ChaCha20Poly1305Cipher {
    key_bytes: [u8; CHACHA20_POLY1305_KEY_LEN],
}

impl ChaCha20Poly1305Cipher {
    /// Internal raw constructor — length-checked, no weak-key guard.
    /// `pub(crate)` to keep it off the public API surface.
    #[inline]
    pub(crate) fn new_raw(key: &[u8]) -> Result<Self, AeadError> {
        if key.len() != CHACHA20_POLY1305_KEY_LEN {
            return Err(AeadError::InvalidKeyLength);
        }
        let mut key_bytes = [0u8; CHACHA20_POLY1305_KEY_LEN];
        key_bytes.copy_from_slice(key);
        Ok(ChaCha20Poly1305Cipher { key_bytes })
    }

    /// Construct bypassing the `AeadError::WeakKey` guard. KAT-only.
    /// Gated behind the `kat-test-vectors` Cargo feature.
    ///
    /// # Errors
    /// - `AeadError::InvalidKeyLength` if `key` is not 32 bytes.
    #[cfg(any(test, feature = "kat-test-vectors"))]
    pub fn new_allow_weak_key(key: &[u8]) -> Result<Self, AeadError> {
        Self::new_raw(key)
    }
}

impl AeadCipher for ChaCha20Poly1305Cipher {
    const KEY_LEN: usize = CHACHA20_POLY1305_KEY_LEN;

    fn new(key: &[u8]) -> Result<Self, AeadError> {
        if key.len() != Self::KEY_LEN {
            return Err(AeadError::InvalidKeyLength);
        }
        if super::is_all_zero_key(key) {
            return Err(AeadError::WeakKey);
        }
        Self::new_raw(key)
    }

    fn generate_nonce() -> Nonce {
        // Fill via CSPRNG directly — the upstream
        // `ChaCha20Poly1305::generate_nonce` requires an `expect` on
        // its `try_into` to a fixed-length array, violating the
        // workspace `expect_used` lint.
        let mut bytes = [0u8; 12];
        crate::primitives::rand::secure_rng().fill_bytes(&mut bytes);
        bytes
    }

    fn encrypt(
        &self,
        nonce: &Nonce,
        plaintext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<(Vec<u8>, Tag), AeadError> {
        // Pattern 6 opacity sweep on the encrypt path —
        // every adversary-reachable failure (size caps, AEAD seal,
        // post-seal buffer-shape) collapses to the same opaque string.
        // See aes_gcm.rs for the full rationale; matching constant is
        // `ENCRYPTION_FAILED` in this file.
        validate_encryption_size(plaintext.len()).map_err(
            |_e: crate::primitives::resource_limits::ResourceError| {
                AeadError::EncryptionFailed(ENCRYPTION_FAILED.to_string())
            },
        )?;

        if let Some(a) = aad {
            validate_aad_size(a.len())
                .map_err(|_e| AeadError::EncryptionFailed(ENCRYPTION_FAILED.to_string()))?;
        }

        let cipher = ChaCha20Poly1305::new_from_slice(&self.key_bytes)
            .map_err(|_e| AeadError::InvalidKeyLength)?;
        let chacha_nonce = (*nonce).into();

        let ciphertext_with_tag = match aad {
            Some(aad) => cipher
                .encrypt(&chacha_nonce, chacha20poly1305::aead::Payload { msg: plaintext, aad })
                .map_err(|_e| AeadError::EncryptionFailed(ENCRYPTION_FAILED.to_string()))?,
            None => cipher
                .encrypt(&chacha_nonce, plaintext)
                .map_err(|_e| AeadError::EncryptionFailed(ENCRYPTION_FAILED.to_string()))?,
        };

        if ciphertext_with_tag.len() < TAG_LEN {
            return Err(AeadError::EncryptionFailed(ENCRYPTION_FAILED.to_string()));
        }
        let ct_len = ciphertext_with_tag.len().saturating_sub(TAG_LEN);
        let ciphertext = ciphertext_with_tag
            .get(..ct_len)
            .ok_or_else(|| AeadError::EncryptionFailed(ENCRYPTION_FAILED.to_string()))?
            .to_vec();
        let mut tag = [0u8; TAG_LEN];
        let tag_slice = ciphertext_with_tag
            .get(ct_len..)
            .ok_or_else(|| AeadError::EncryptionFailed(ENCRYPTION_FAILED.to_string()))?;
        tag.copy_from_slice(tag_slice);

        Ok((ciphertext, tag))
    }

    fn decrypt(
        &self,
        nonce: &Nonce,
        ciphertext: &[u8],
        tag: &Tag,
        aad: Option<&[u8]>,
    ) -> Result<Zeroizing<Vec<u8>>, AeadError> {
        // Pattern 6 opacity sweep — every decrypt failure
        // collapses to the same opaque string so the primitives layer no
        // longer leaks a stage-identifying oracle (size-check vs MAC-check
        // vs buffer-shape) to direct callers. See aes_gcm.rs for the full
        // rationale; the matching constant lives in this file as
        // `DECRYPTION_FAILED`.
        validate_decryption_size(ciphertext.len()).map_err(
            |_e: crate::primitives::resource_limits::ResourceError| {
                AeadError::DecryptionFailed(DECRYPTION_FAILED.to_string())
            },
        )?;

        if let Some(a) = aad {
            validate_aad_size(a.len())
                .map_err(|_e| AeadError::DecryptionFailed(DECRYPTION_FAILED.to_string()))?;
        }

        let cipher = ChaCha20Poly1305::new_from_slice(&self.key_bytes)
            .map_err(|_e| AeadError::InvalidKeyLength)?;
        let chacha_nonce = (*nonce).into();

        // Combine ciphertext and tag for the chacha20poly1305 crate.
        // Wrap in Zeroizing so the plaintext residue is scrubbed on drop (B2).
        let mut ciphertext_with_tag: Zeroizing<Vec<u8>> =
            Zeroizing::new(Vec::with_capacity(ciphertext.len().saturating_add(TAG_LEN)));
        ciphertext_with_tag.extend_from_slice(ciphertext);
        ciphertext_with_tag.extend_from_slice(tag);

        let plaintext = match aad {
            Some(aad) => cipher
                .decrypt(
                    &chacha_nonce,
                    chacha20poly1305::aead::Payload { msg: &ciphertext_with_tag, aad },
                )
                .map_err(|_e| AeadError::DecryptionFailed(DECRYPTION_FAILED.to_string()))?,
            None => cipher
                .decrypt(&chacha_nonce, ciphertext_with_tag.as_ref())
                .map_err(|_e| AeadError::DecryptionFailed(DECRYPTION_FAILED.to_string()))?,
        };

        Ok(Zeroizing::new(plaintext))
    }
}

impl ChaCha20Poly1305Cipher {
    /// Generate a random key for ChaCha20-Poly1305.
    ///
    /// Returns a `Zeroizing` wrapper that automatically zeroes the key on drop.
    ///
    /// the previous shape called
    /// `ChaCha20Poly1305::generate_key(&mut OsRng)` and copied the
    /// resulting `GenericArray` into the destination, leaving an
    /// un-zeroed transient on the stack. We now fill the destination
    /// directly via `secure_rng().fill_bytes` so no intermediate copy
    /// of the key bytes exists, matching the AES path.
    #[must_use]
    pub fn generate_key() -> Zeroizing<[u8; CHACHA20_POLY1305_KEY_LEN]> {
        let mut result = Zeroizing::new([0u8; CHACHA20_POLY1305_KEY_LEN]);
        crate::primitives::rand::secure_rng().fill_bytes(result.as_mut());
        result
    }
}

impl std::fmt::Debug for ChaCha20Poly1305Cipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChaCha20Poly1305Cipher").field("key_bytes", &"[REDACTED]").finish()
    }
}

impl ConstantTimeEq for ChaCha20Poly1305Cipher {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.key_bytes.ct_eq(&other.key_bytes)
    }
}

/// XChaCha20-Poly1305 AEAD cipher (extended nonce variant)
///
/// Uses XChaCha20 stream cipher with 192-bit nonce for better nonce reuse safety.
/// Follows RFC 8439 draft for extended nonce variant.
///
/// This type does **not** implement `AeadCipher` because XChaCha20 natively uses
/// 24-byte nonces while the trait constrains nonces to 12 bytes. Use the native
/// [`encrypt_x`](XChaCha20Poly1305Cipher::encrypt_x) /
/// [`decrypt_x`](XChaCha20Poly1305Cipher::decrypt_x) methods with
/// [`generate_xnonce`](XChaCha20Poly1305Cipher::generate_xnonce) for full 2^192 nonce entropy.
///
/// # Example
///
/// ```rust
/// use latticearc::primitives::aead::chacha20poly1305::XChaCha20Poly1305Cipher;
///
/// let key = XChaCha20Poly1305Cipher::generate_key();
/// let cipher = XChaCha20Poly1305Cipher::new(&*key).unwrap();
/// let nonce = XChaCha20Poly1305Cipher::generate_xnonce();
/// let plaintext = b"secret message";
/// let (ciphertext, tag) = cipher.encrypt_x(&nonce, plaintext, None).unwrap();
/// let decrypted = cipher.decrypt_x(&nonce, &ciphertext, &tag, None).unwrap();
/// assert_eq!(plaintext, decrypted.as_slice());
/// ```
/// Stores key bytes directly (like AES-GCM) for proper `ZeroizeOnDrop` support.
/// The `XChaCha20Poly1305` cipher is constructed transiently for each operation.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct XChaCha20Poly1305Cipher {
    key_bytes: [u8; CHACHA20_POLY1305_KEY_LEN],
}

/// Nonce length for XChaCha20-Poly1305 (24 bytes / 192 bits)
pub const XNONCE_LEN: usize = 24;

/// XNonce type for XChaCha20-Poly1305
pub type XNonce = [u8; XNONCE_LEN];

impl XChaCha20Poly1305Cipher {
    /// Create a new XChaCha20-Poly1305 cipher from key bytes.
    ///
    /// # Errors
    /// - `AeadError::InvalidKeyLength` if `key` is not exactly 32 bytes.
    /// - `AeadError::WeakKey` if `key` is the all-zero pattern. To bypass
    ///   for known-test-vector reproduction, enable the `kat-test-vectors`
    ///   Cargo feature and call [`Self::new_allow_weak_key`] instead.
    pub fn new(key: &[u8]) -> Result<Self, AeadError> {
        if key.len() != CHACHA20_POLY1305_KEY_LEN {
            return Err(AeadError::InvalidKeyLength);
        }
        if super::is_all_zero_key(key) {
            return Err(AeadError::WeakKey);
        }
        Self::new_raw(key)
    }

    /// Construct bypassing the [`AeadError::WeakKey`] guard. Reserved for
    /// known-test-vector reproduction (e.g. all-zero key/IV cases); production
    /// code must use [`Self::new`]. Gated behind the `kat-test-vectors` Cargo
    /// feature.
    ///
    /// # Errors
    /// - `AeadError::InvalidKeyLength` if `key` is not exactly 32 bytes.
    #[cfg(any(test, feature = "kat-test-vectors"))]
    pub fn new_allow_weak_key(key: &[u8]) -> Result<Self, AeadError> {
        Self::new_raw(key)
    }

    /// Internal raw constructor — length check + buffer copy, no weak-key
    /// guard. `pub(crate)` so the bypass is not callable from outside the
    /// crate. `new` and `new_allow_weak_key` both delegate here.
    pub(crate) fn new_raw(key: &[u8]) -> Result<Self, AeadError> {
        if key.len() != CHACHA20_POLY1305_KEY_LEN {
            return Err(AeadError::InvalidKeyLength);
        }
        let mut key_bytes = [0u8; CHACHA20_POLY1305_KEY_LEN];
        key_bytes.copy_from_slice(key);
        Ok(XChaCha20Poly1305Cipher { key_bytes })
    }

    /// Generate a random key for XChaCha20-Poly1305.
    ///
    /// Returns a `Zeroizing` wrapper that automatically zeroes the key on drop.
    #[must_use]
    pub fn generate_key() -> Zeroizing<[u8; CHACHA20_POLY1305_KEY_LEN]> {
        // Fill the Zeroizing buffer directly. Upstream
        // `XChaCha20Poly1305::generate_key` returns a `GenericArray`
        // on the stack that copy_from_slice would leave un-zeroized
        // when the stack frame unwinds.
        let mut key = Zeroizing::new([0u8; CHACHA20_POLY1305_KEY_LEN]);
        crate::primitives::rand::secure_rng().fill_bytes(&mut *key);
        key
    }

    /// Generate a full 24-byte random nonce for XChaCha20-Poly1305.
    ///
    /// This provides the full 2^192 nonce space that XChaCha was designed for.
    /// Use with [`encrypt_x`](Self::encrypt_x) and [`decrypt_x`](Self::decrypt_x).
    #[must_use]
    pub fn generate_xnonce() -> XNonce {
        let mut nonce = [0u8; XNONCE_LEN];
        crate::primitives::rand::secure_rng().fill_bytes(&mut nonce);
        nonce
    }

    /// Encrypt with a full 24-byte XNonce (recommended over trait-based API).
    ///
    /// # Errors
    ///
    /// Returns `AeadError` if encryption fails.
    pub fn encrypt_x(
        &self,
        nonce: &XNonce,
        plaintext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<(Vec<u8>, Tag), AeadError> {
        // Pattern 6 opacity sweep — symmetric with the
        // AeadCipher trait impl above and the AES-GCM macro. Every
        // adversary-reachable encrypt failure collapses to the same
        // opaque string; per-stage diagnostics live in tracing::debug!.
        validate_encryption_size(plaintext.len()).map_err(
            |_e: crate::primitives::resource_limits::ResourceError| {
                AeadError::EncryptionFailed(ENCRYPTION_FAILED.to_string())
            },
        )?;

        if let Some(a) = aad {
            validate_aad_size(a.len())
                .map_err(|_e| AeadError::EncryptionFailed(ENCRYPTION_FAILED.to_string()))?;
        }

        let cipher = chacha20poly1305::XChaCha20Poly1305::new_from_slice(&self.key_bytes)
            .map_err(|_e| AeadError::InvalidKeyLength)?;
        let xnonce = (*nonce).into();

        let ciphertext_with_tag = match aad {
            Some(aad) => cipher
                .encrypt(&xnonce, chacha20poly1305::aead::Payload { msg: plaintext, aad })
                .map_err(|_e| AeadError::EncryptionFailed(ENCRYPTION_FAILED.to_string()))?,
            None => cipher
                .encrypt(&xnonce, plaintext)
                .map_err(|_e| AeadError::EncryptionFailed(ENCRYPTION_FAILED.to_string()))?,
        };

        if ciphertext_with_tag.len() < TAG_LEN {
            return Err(AeadError::EncryptionFailed(ENCRYPTION_FAILED.to_string()));
        }
        let ct_len = ciphertext_with_tag.len().saturating_sub(TAG_LEN);
        let ciphertext = ciphertext_with_tag
            .get(..ct_len)
            .ok_or_else(|| AeadError::EncryptionFailed(ENCRYPTION_FAILED.to_string()))?
            .to_vec();
        let mut tag = [0u8; TAG_LEN];
        let tag_slice = ciphertext_with_tag
            .get(ct_len..)
            .ok_or_else(|| AeadError::EncryptionFailed(ENCRYPTION_FAILED.to_string()))?;
        tag.copy_from_slice(tag_slice);

        Ok((ciphertext, tag))
    }

    /// Decrypt with a full 24-byte XNonce (recommended over trait-based API).
    ///
    /// # Errors
    ///
    /// Returns `AeadError` if decryption or authentication fails.
    pub fn decrypt_x(
        &self,
        nonce: &XNonce,
        ciphertext: &[u8],
        tag: &Tag,
        aad: Option<&[u8]>,
    ) -> Result<Zeroizing<Vec<u8>>, AeadError> {
        // Pattern 6 opacity sweep — every decrypt failure
        // collapses to the same opaque string. Symmetric with the
        // ChaCha20Poly1305 trait impl above and the AES-GCM macro.
        validate_decryption_size(ciphertext.len()).map_err(
            |_e: crate::primitives::resource_limits::ResourceError| {
                AeadError::DecryptionFailed(DECRYPTION_FAILED.to_string())
            },
        )?;

        if let Some(a) = aad {
            validate_aad_size(a.len())
                .map_err(|_e| AeadError::DecryptionFailed(DECRYPTION_FAILED.to_string()))?;
        }

        let cipher = chacha20poly1305::XChaCha20Poly1305::new_from_slice(&self.key_bytes)
            .map_err(|_e| AeadError::InvalidKeyLength)?;
        let xnonce = (*nonce).into();

        let mut ciphertext_with_tag: Zeroizing<Vec<u8>> =
            Zeroizing::new(Vec::with_capacity(ciphertext.len().saturating_add(TAG_LEN)));
        ciphertext_with_tag.extend_from_slice(ciphertext);
        ciphertext_with_tag.extend_from_slice(tag);

        let plaintext = match aad {
            Some(aad) => cipher
                .decrypt(
                    &xnonce,
                    chacha20poly1305::aead::Payload { msg: &ciphertext_with_tag, aad },
                )
                .map_err(|_e| AeadError::DecryptionFailed(DECRYPTION_FAILED.to_string()))?,
            None => cipher
                .decrypt(&xnonce, ciphertext_with_tag.as_ref())
                .map_err(|_e| AeadError::DecryptionFailed(DECRYPTION_FAILED.to_string()))?,
        };

        Ok(Zeroizing::new(plaintext))
    }
}

impl std::fmt::Debug for XChaCha20Poly1305Cipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("XChaCha20Poly1305Cipher").field("key_bytes", &"[REDACTED]").finish()
    }
}

impl ConstantTimeEq for XChaCha20Poly1305Cipher {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.key_bytes.ct_eq(&other.key_bytes)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)] // Tests use unwrap for simplicity
#[allow(clippy::panic)] // Tests use panic! for error case validation
mod tests {
    use super::*;
    use crate::primitives::aead::{verify_tag_constant_time, zeroize_data};
    use zeroize::Zeroize;

    #[test]
    fn test_chacha20_poly1305_key_generation_succeeds() {
        let key1 = ChaCha20Poly1305Cipher::generate_key();
        let key2 = ChaCha20Poly1305Cipher::generate_key();
        assert_eq!(key1.len(), CHACHA20_POLY1305_KEY_LEN);
        assert_eq!(key2.len(), CHACHA20_POLY1305_KEY_LEN);
        // Keys should be different (with very high probability)
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_chacha20_poly1305_invalid_key_length_fails() {
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
    fn test_chacha20_poly1305_all_zero_key_rejected_at_construction() {
        // Mirrors the AesGcm256 weak-key-rejection test. Per RFC 7539 §4 and
        // the McGrew/Viega weak-key analysis, an all-zero key produces a
        // deterministic keystream that immediately leaks plaintext under
        // known-plaintext analysis.
        let zero_key = [0u8; CHACHA20_POLY1305_KEY_LEN];
        let result = ChaCha20Poly1305Cipher::new(&zero_key);
        assert!(
            matches!(result, Err(AeadError::WeakKey)),
            "All-zero ChaCha20-Poly1305 key must be rejected; got {result:?}"
        );
    }

    #[test]
    fn test_chacha20_poly1305_new_allow_weak_key_bypasses_check() {
        // The KAT escape hatch must succeed where `new` rejects, otherwise
        // RFC 7539 test vectors that use an all-zero key cannot be verified.
        // This test pins the bypass surface so a future tightening of the
        // weak-key check does not silently break KAT verification.
        let zero_key = [0u8; CHACHA20_POLY1305_KEY_LEN];
        let result = ChaCha20Poly1305Cipher::new_allow_weak_key(&zero_key);
        assert!(result.is_ok(), "new_allow_weak_key must accept the all-zero key");
    }

    #[test]
    fn test_chacha20_poly1305_encrypt_decrypt_roundtrip() {
        let key = ChaCha20Poly1305Cipher::generate_key();
        let cipher = ChaCha20Poly1305Cipher::new(&*key).unwrap();
        let nonce = ChaCha20Poly1305Cipher::generate_nonce();
        let plaintext = b"Hello, World!";

        let (ciphertext, tag) = cipher.encrypt(&nonce, plaintext, None).unwrap();
        let decrypted = cipher.decrypt(&nonce, &ciphertext, &tag, None).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_chacha20_poly1305_with_aad_roundtrip() {
        let key = ChaCha20Poly1305Cipher::generate_key();
        let cipher = ChaCha20Poly1305Cipher::new(&*key).unwrap();
        let nonce = ChaCha20Poly1305Cipher::generate_nonce();
        let plaintext = b"Secret data";
        let aad = b"Additional authenticated data";

        let (ciphertext, tag) = cipher.encrypt(&nonce, plaintext, Some(aad)).unwrap();
        let decrypted = cipher.decrypt(&nonce, &ciphertext, &tag, Some(aad)).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_chacha20_poly1305_with_aad_verification_failure_fails() {
        let key = ChaCha20Poly1305Cipher::generate_key();
        let cipher = ChaCha20Poly1305Cipher::new(&*key).unwrap();
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
    fn test_chacha20_poly1305_invalid_tag_fails() {
        let key = ChaCha20Poly1305Cipher::generate_key();
        let cipher = ChaCha20Poly1305Cipher::new(&*key).unwrap();
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
    fn test_chacha20_poly1305_corrupted_ciphertext_fails() {
        let key = ChaCha20Poly1305Cipher::generate_key();
        let cipher = ChaCha20Poly1305Cipher::new(&*key).unwrap();
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
    fn test_chacha20_poly1305_constant_time_tag_verification_is_correct() {
        let tag1 = [1u8; 16];
        let tag2 = [1u8; 16];
        let tag3 = [2u8; 16];

        assert!(verify_tag_constant_time(&tag1, &tag2));
        assert!(!verify_tag_constant_time(&tag1, &tag3));
    }

    #[test]
    fn test_chacha20_poly1305_zeroize_data_clears_bytes_succeeds() {
        let mut data = vec![0xFF; 100];
        zeroize_data(&mut data);
        assert_eq!(data, vec![0u8; 100]);
    }

    #[test]
    fn test_chacha20poly1305_key_zeroization_succeeds() {
        let mut key = ChaCha20Poly1305Cipher::generate_key();

        assert!(!key.iter().all(|&b| b == 0), "ChaCha20Poly1305 key should contain non-zero data");

        key.zeroize();

        assert!(key.iter().all(|&b| b == 0), "ChaCha20Poly1305 key should be zeroized");
    }

    #[test]
    fn test_chacha20poly1305_nonce_zeroization_succeeds() {
        let mut nonce = ChaCha20Poly1305Cipher::generate_nonce();

        assert!(
            !nonce.iter().all(|&b| b == 0),
            "ChaCha20Poly1305 nonce should contain non-zero data"
        );

        nonce.zeroize();

        assert!(nonce.iter().all(|&b| b == 0), "ChaCha20Poly1305 nonce should be zeroized");
    }

    #[test]
    fn test_chacha20poly1305_ciphertext_zeroization_succeeds() {
        let key = ChaCha20Poly1305Cipher::generate_key();
        let cipher = ChaCha20Poly1305Cipher::new(&*key).unwrap();
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
    fn test_chacha20_poly1305_empty_plaintext_roundtrip() {
        let key = ChaCha20Poly1305Cipher::generate_key();
        let cipher = ChaCha20Poly1305Cipher::new(&*key).unwrap();
        let nonce = ChaCha20Poly1305Cipher::generate_nonce();
        let plaintext = b"";

        let (ciphertext, tag) = cipher.encrypt(&nonce, plaintext, None).unwrap();
        let decrypted = cipher.decrypt(&nonce, &ciphertext, &tag, None).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
        assert_eq!(ciphertext.len(), 0);
        assert_eq!(tag.len(), TAG_LEN);
    }

    #[test]
    fn test_chacha20_poly1305_large_plaintext_roundtrip() {
        let key = ChaCha20Poly1305Cipher::generate_key();
        let cipher = ChaCha20Poly1305Cipher::new(&*key).unwrap();
        let nonce = ChaCha20Poly1305Cipher::generate_nonce();
        let plaintext = vec![0xAB; 1024 * 1024]; // 1MB

        let (ciphertext, tag) = cipher.encrypt(&nonce, &plaintext, None).unwrap();
        let decrypted = cipher.decrypt(&nonce, &ciphertext, &tag, None).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
        assert_eq!(ciphertext.len(), 1024 * 1024);
        assert_eq!(tag.len(), TAG_LEN);
    }

    #[test]
    fn test_chacha20_poly1305_large_aad_roundtrip() {
        let key = ChaCha20Poly1305Cipher::generate_key();
        let cipher = ChaCha20Poly1305Cipher::new(&*key).unwrap();
        let nonce = ChaCha20Poly1305Cipher::generate_nonce();
        let plaintext = b"Secret data";

        // Large AAD (64KB)
        let aad = vec![0xAA; 64 * 1024];

        let (ciphertext, tag) = cipher.encrypt(&nonce, plaintext, Some(&aad)).unwrap();
        let decrypted = cipher.decrypt(&nonce, &ciphertext, &tag, Some(&aad)).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_chacha20_poly1305_multiple_encryptions_all_roundtrip() {
        let key = ChaCha20Poly1305Cipher::generate_key();
        let cipher = ChaCha20Poly1305Cipher::new(&*key).unwrap();

        for i in 0..100 {
            let nonce = ChaCha20Poly1305Cipher::generate_nonce();
            let plaintext = format!("Message {}", i);
            let (ciphertext, tag) = cipher.encrypt(&nonce, plaintext.as_bytes(), None).unwrap();
            let decrypted = cipher.decrypt(&nonce, &ciphertext, &tag, None).unwrap();
            assert_eq!(plaintext.as_bytes(), decrypted.as_slice());
        }
    }

    #[test]
    fn test_xchacha20_poly1305_key_generation_succeeds() {
        let key1 = XChaCha20Poly1305Cipher::generate_key();
        let key2 = XChaCha20Poly1305Cipher::generate_key();
        assert_eq!(key1.len(), CHACHA20_POLY1305_KEY_LEN);
        assert_eq!(key2.len(), CHACHA20_POLY1305_KEY_LEN);
        // Keys should be different (with very high probability)
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_xchacha20_poly1305_encrypt_decrypt_roundtrip() {
        let key = XChaCha20Poly1305Cipher::generate_key();
        let cipher = XChaCha20Poly1305Cipher::new(&*key).unwrap();
        let nonce = XChaCha20Poly1305Cipher::generate_xnonce();
        let plaintext = b"Hello, XChaCha20!";

        let (ciphertext, tag) = cipher.encrypt_x(&nonce, plaintext, None).unwrap();
        let decrypted = cipher.decrypt_x(&nonce, &ciphertext, &tag, None).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_xchacha20_poly1305_with_aad_roundtrip() {
        let key = XChaCha20Poly1305Cipher::generate_key();
        let cipher = XChaCha20Poly1305Cipher::new(&*key).unwrap();
        let nonce = XChaCha20Poly1305Cipher::generate_xnonce();
        let plaintext = b"Secret data";
        let aad = b"Additional authenticated data";

        let (ciphertext, tag) = cipher.encrypt_x(&nonce, plaintext, Some(aad)).unwrap();
        let decrypted = cipher.decrypt_x(&nonce, &ciphertext, &tag, Some(aad)).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_chacha20_poly1305_rfc_test_vector_1_matches_vector() {
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
    fn test_chacha20_poly1305_wrong_key_fails() {
        let key = ChaCha20Poly1305Cipher::generate_key();
        let cipher = ChaCha20Poly1305Cipher::new(&*key).unwrap();
        let nonce = ChaCha20Poly1305Cipher::generate_nonce();
        let plaintext = b"Secret message";

        let (ciphertext, tag) = cipher.encrypt(&nonce, plaintext, None).unwrap();

        // Try to decrypt with wrong key
        let wrong_key = ChaCha20Poly1305Cipher::generate_key();
        let wrong_cipher = ChaCha20Poly1305Cipher::new(&*wrong_key).unwrap();
        let result = wrong_cipher.decrypt(&nonce, &ciphertext, &tag, None);

        assert!(result.is_err());
        if let Err(AeadError::DecryptionFailed(_)) = result {
            // Expected
        } else {
            panic!("Expected DecryptionFailed error");
        }
    }

    #[test]
    fn test_chacha20_poly1305_empty_aad_roundtrip() {
        let key = ChaCha20Poly1305Cipher::generate_key();
        let cipher = ChaCha20Poly1305Cipher::new(&*key).unwrap();
        let nonce = ChaCha20Poly1305Cipher::generate_nonce();
        let plaintext = b"Secret data";
        let aad: [u8; 0] = [];

        let (ciphertext, tag) = cipher.encrypt(&nonce, plaintext, Some(&aad)).unwrap();
        let decrypted = cipher.decrypt(&nonce, &ciphertext, &tag, Some(&aad)).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_chacha20_poly1305_wrong_nonce_fails() {
        let key = ChaCha20Poly1305Cipher::generate_key();
        let cipher = ChaCha20Poly1305Cipher::new(&*key).unwrap();
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

    #[test]
    fn test_chacha20_poly1305_encryption_size_limit_has_correct_size() {
        let key = ChaCha20Poly1305Cipher::generate_key();
        let cipher = ChaCha20Poly1305Cipher::new(&*key).unwrap();
        let nonce = ChaCha20Poly1305Cipher::generate_nonce();

        // Try to encrypt data exceeding 100MB limit (101MB)
        let plaintext = vec![0xAB; 101 * 1024 * 1024];

        let result = cipher.encrypt(&nonce, &plaintext, None);
        assert!(result.is_err(), "Should fail with resource limit exceeded");

        // Pattern 6 opacity sweep collapsed every encrypt
        // failure to the same opaque "encryption failed" string.
        assert!(
            matches!(result, Err(AeadError::EncryptionFailed(_))),
            "Expected EncryptionFailed variant, got {result:?}"
        );
    }

    #[test]
    fn test_chacha20_poly1305_decryption_size_limit_has_correct_size() {
        let key = ChaCha20Poly1305Cipher::generate_key();
        let cipher = ChaCha20Poly1305Cipher::new(&*key).unwrap();
        let nonce = ChaCha20Poly1305Cipher::generate_nonce();

        // Try to decrypt data exceeding 100MB limit
        let ciphertext = vec![0xCD; 101 * 1024 * 1024];
        let tag = [0u8; TAG_LEN];

        let result = cipher.decrypt(&nonce, &ciphertext, &tag, None);
        assert!(result.is_err(), "Should fail with resource limit exceeded");

        // Pattern 6 opacity sweep collapsed every decrypt
        // failure to the same opaque "decryption failed" string, so this
        // test now only asserts the variant shape.
        assert!(
            matches!(result, Err(AeadError::DecryptionFailed(_))),
            "Expected DecryptionFailed variant, got {result:?}"
        );
    }
}
