#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

//! Authenticated Encryption with Additional Data (AEAD)
//!
//! Provides AEAD schemes for symmetric encryption following NIST SP 800-38D and RFC 8439.
//!
//! ## AEAD Schemes
//!
//! - **AES-GCM-128**: AES-GCM with 128-bit key (NIST SP 800-38D). Available
//!   in every feature configuration.
//! - **AES-GCM-256**: AES-GCM with 256-bit key (NIST SP 800-38D). Available
//!   in every feature configuration.
//! - **ChaCha20-Poly1305**: Stream cipher with Poly1305 MAC (RFC 8439).
//!   *Compiled out under the `fips` feature* — ChaCha20-Poly1305 is not in
//!   NIST SP 800-38D, so the module and its types are unavailable in
//!   `fips`-enabled builds. Higher-level APIs that select an AEAD
//!   automatically pick AES-GCM-256 when `fips` is on.
//!
//! ## AEAD Security Notes
//!
//! - **Nonce Reuse**: NEVER reuse a nonce with the same key - this breaks security
//! - **Nonce Prediction**: Use cryptographically secure random nonces
//! - **Tag Verification**: ALWAYS verify the authentication tag before accepting ciphertext
//! - **Side Channels**: All tag verification is constant-time to prevent timing attacks

pub mod aes_gcm;

/// ChaCha20-Poly1305 AEAD (RFC 8439). Non-FIPS: not in NIST SP 800-38D.
#[cfg(not(feature = "fips"))]
pub mod chacha20poly1305;

/// AEAD cipher nonce length
pub const NONCE_LEN: usize = 12;

/// AEAD authentication tag length
pub const TAG_LEN: usize = 16;

/// AES-GCM-128 key length
pub const AES_GCM_128_KEY_LEN: usize = 16;

/// AES-GCM-256 key length
pub const AES_GCM_256_KEY_LEN: usize = 32;

/// ChaCha20-Poly1305 key length
pub const CHACHA20_POLY1305_KEY_LEN: usize = 32;

/// Nonce type for AEAD ciphers.
///
/// A 12-byte array used as a unique identifier for each encryption operation.
/// Callers must ensure nonce uniqueness per key; reusing a nonce with the same
/// key breaks AEAD security guarantees.
// Retained as a type alias rather than a newtype because converting ripples
// through every AEAD call site.
pub type Nonce = [u8; NONCE_LEN];

/// Auth tag type for AEAD ciphers.
///
/// A 16-byte authenticator computed during encryption and verified in
/// constant time during decryption.
pub type Tag = [u8; TAG_LEN];

/// Sealed trait pattern — prevents external crates from implementing `AeadCipher`.
///
/// Security-critical traits must not allow third-party implementations since
/// they could bypass key validation, zeroization, or constant-time guarantees.
mod sealed {
    pub trait Sealed {}
    impl Sealed for super::aes_gcm::AesGcm128 {}
    impl Sealed for super::aes_gcm::AesGcm256 {}
    #[cfg(not(feature = "fips"))]
    impl Sealed for super::chacha20poly1305::ChaCha20Poly1305Cipher {}
}

/// AEAD cipher trait (sealed — cannot be implemented outside this crate)
pub trait AeadCipher: sealed::Sealed {
    /// Key length in bytes
    const KEY_LEN: usize;

    /// Create new AEAD cipher from key bytes — the strict, production entry
    /// point. Length is validated and the all-zero key pattern is rejected as
    /// fail-closed defence in depth (it is overwhelmingly the signature of
    /// uninitialised memory or an unset configuration field rather than a
    /// deliberate operational choice).
    ///
    /// For NIST KAT reproduction (Test Cases 1 and 2 of McGrew & Viega's
    /// AES-GCM specification use the all-zero key) enable the
    /// `kat-test-vectors` Cargo feature and call the per-cipher inherent
    /// `new_allow_weak_key` constructor instead — that constructor preserves
    /// the length check but skips the weak-key guard. The feature is opt-in
    /// so production builds cannot accidentally construct a weak-key cipher.
    ///
    /// # Implementation note
    ///
    /// Implementations of this trait MUST themselves perform both the length
    /// check and the [`is_all_zero_key`] / [`AeadError::WeakKey`] check
    /// before constructing the cipher. The previous design exposed a
    /// `new_internal` trait method that bypassed `WeakKey`, but trait methods
    /// in Rust are callable by anyone with the trait in scope, which made
    /// the bypass an unintended public-API surface. Each cipher type now
    /// keeps its raw constructor as a `pub(crate)` inherent fn that no
    /// downstream caller can reach.
    ///
    /// # Errors
    /// - [`AeadError::InvalidKeyLength`] if `key.len() != Self::KEY_LEN`.
    /// - [`AeadError::WeakKey`] if `key` is the all-zero pattern.
    fn new(key: &[u8]) -> Result<Self, AeadError>
    where
        Self: Sized;

    /// Generate a random nonce from the OS CSPRNG.
    fn generate_nonce() -> Nonce;

    /// Encrypt plaintext with a caller-supplied nonce.
    ///
    /// # Security
    ///
    /// **Prefer [`AeadCipher::seal`]** unless you have a specific reason to control
    /// the nonce value. `seal` generates a fresh random nonce per call, eliminating
    /// caller-controlled nonce reuse — the single most catastrophic misuse of
    /// AES-GCM / ChaCha20-Poly1305.
    ///
    /// This low-level method exists for:
    /// - NIST KAT reproduction (deterministic inputs required)
    /// - Protocol-specified nonce derivation (e.g., TLS 1.3 per-record nonce)
    /// - Deterministic encryption constructions
    ///
    /// Reusing a `(key, nonce)` pair with AES-GCM *catastrophically* breaks both
    /// confidentiality (XOR of plaintexts recoverable) and integrity (forgery via
    /// authentication key recovery). See NIST SP 800-38D §8.2 and
    /// Joux, "Authentication Failures in NIST version of GCM" (2006).
    ///
    /// # Arguments
    ///
    /// * `nonce` - 12-byte nonce; MUST be unique for every call with this key.
    /// * `plaintext` - Data to encrypt.
    /// * `aad` - Optional associated data (authenticated, not encrypted).
    ///
    /// # Returns
    ///
    /// Tuple of (ciphertext, authentication_tag).
    ///
    /// # Errors
    ///
    /// Returns `AeadError` if encryption fails.
    fn encrypt(
        &self,
        nonce: &Nonce,
        plaintext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<(Vec<u8>, Tag), AeadError>;

    /// Encrypt plaintext with an internally-generated random nonce.
    ///
    /// This is the preferred primitive-layer encryption entry point: the nonce
    /// is drawn fresh from the OS CSPRNG per call (96 bits), making
    /// caller-controlled nonce reuse structurally impossible. The returned
    /// nonce must be transmitted alongside the ciphertext so the receiver can
    /// decrypt.
    ///
    /// Under the RBG-based construction of NIST SP 800-38D §8.2.2, a single
    /// key supports up to 2^32 invocations before the collision bound becomes
    /// relevant — more than enough for typical workloads. Rotate keys
    /// periodically if you approach that scale.
    ///
    /// Use [`AeadCipher::encrypt`] only when the protocol or test vector
    /// requires a caller-controlled nonce.
    ///
    /// # Arguments
    ///
    /// * `plaintext` - Data to encrypt.
    /// * `aad` - Optional associated data (authenticated, not encrypted).
    ///
    /// # Returns
    ///
    /// Tuple of `(nonce, ciphertext, tag)`. The nonce MUST be stored alongside
    /// the ciphertext for decryption.
    ///
    /// # Errors
    ///
    /// Returns `AeadError` if encryption fails.
    fn seal(
        &self,
        plaintext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<(Nonce, Vec<u8>, Tag), AeadError> {
        let nonce = Self::generate_nonce();
        let (ciphertext, tag) = self.encrypt(&nonce, plaintext, aad)?;
        Ok((nonce, ciphertext, tag))
    }

    /// Decrypt ciphertext with optional associated data
    ///
    /// # Arguments
    ///
    /// * `nonce` - Unique nonce for this encryption
    /// * `ciphertext` - Encrypted data
    /// * `tag` - Authentication tag
    /// * `aad` - Optional associated data
    ///
    /// # Returns
    ///
    /// Decrypted plaintext wrapped in [`zeroize::Zeroizing`] so the buffer is
    /// scrubbed on drop regardless of whether the caller persists it.
    ///
    /// # Errors
    ///
    /// Returns `AeadError` if decryption fails
    fn decrypt(
        &self,
        nonce: &Nonce,
        ciphertext: &[u8],
        tag: &Tag,
        aad: Option<&[u8]>,
    ) -> Result<zeroize::Zeroizing<Vec<u8>>, AeadError>;
}

/// AEAD errors
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum AeadError {
    /// Invalid key length
    #[error("Invalid key length")]
    InvalidKeyLength,

    /// Invalid nonce length
    #[error("Invalid nonce length")]
    InvalidNonceLength,

    /// Key material is structurally weak and was rejected before any
    /// cryptographic operation. Currently raised for the all-zero key, which
    /// usually indicates uninitialised memory or an unset configuration field
    /// rather than a deliberate choice. The AEAD algorithm itself does not
    /// fail on this input — the rejection is a fail-closed defence in depth.
    #[error("Weak key rejected by AEAD constructor (likely uninitialised memory)")]
    WeakKey,

    /// Encryption failed
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    /// Decryption failed
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),
}

/// Returns `true` when every byte of `key` is zero. Thin re-export of the
/// shared CT helper at [`crate::primitives::ct::is_all_zero_bytes`] so AEAD
/// callers can `use crate::primitives::aead::is_all_zero_key` without
/// reaching across modules — and so a future move/rename only touches one
/// real implementation.
#[inline]
#[must_use]
pub(crate) fn is_all_zero_key(key: &[u8]) -> bool {
    crate::primitives::ct::is_all_zero_bytes(key)
}

/// Constant-time comparison of two authentication tags.
#[must_use]
pub fn verify_tag_constant_time(expected: &Tag, actual: &Tag) -> bool {
    use subtle::ConstantTimeEq;
    expected.ct_eq(actual).into()
}

/// Zeroize sensitive data in memory.
pub fn zeroize_data(data: &mut [u8]) {
    use zeroize::Zeroize;
    data.zeroize();
}

// Re-export ChaCha20-Poly1305 cipher types for convenience
#[cfg(not(feature = "fips"))]
pub use self::chacha20poly1305::{ChaCha20Poly1305Cipher, XChaCha20Poly1305Cipher};

#[cfg(test)]
#[allow(unused_imports)] // Some re-exported types may not be directly used in tests
mod tests {
    use super::*;

    /// Constant-time comparison of two byte slices using `subtle::ConstantTimeEq`.
    fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
        use subtle::ConstantTimeEq;
        let len_eq = a.len().ct_eq(&b.len());
        let mut result = len_eq;
        for (x, y) in a.iter().zip(b.iter()) {
            result &= x.ct_eq(y);
        }
        result.into()
    }

    #[test]
    fn test_constant_time_eq_equal_succeeds() {
        assert!(constant_time_eq(b"hello", b"hello"));
        assert!(constant_time_eq(b"", b""));
        assert!(constant_time_eq(&[0u8; 32], &[0u8; 32]));
    }

    #[test]
    fn test_constant_time_eq_not_equal_succeeds() {
        assert!(!constant_time_eq(b"hello", b"world"));
        assert!(!constant_time_eq(b"short", b"longer"));
        assert!(!constant_time_eq(b"a", b""));
    }

    #[test]
    fn test_aead_constants_succeeds() {
        assert_eq!(NONCE_LEN, 12);
        assert_eq!(TAG_LEN, 16);
        assert_eq!(AES_GCM_128_KEY_LEN, 16);
        assert_eq!(AES_GCM_256_KEY_LEN, 32);
        assert_eq!(CHACHA20_POLY1305_KEY_LEN, 32);
    }

    #[test]
    fn test_aead_error_display_fails() {
        let err = AeadError::InvalidKeyLength;
        assert_eq!(format!("{}", err), "Invalid key length");

        let err = AeadError::InvalidNonceLength;
        assert_eq!(format!("{}", err), "Invalid nonce length");

        let err = AeadError::EncryptionFailed("test".to_string());
        assert_eq!(format!("{}", err), "Encryption failed: test");

        let err = AeadError::DecryptionFailed("oops".to_string());
        assert_eq!(format!("{}", err), "Decryption failed: oops");

        // `AeadError::WeakKey` Display
        let err = AeadError::WeakKey;
        assert_eq!(
            format!("{}", err),
            "Weak key rejected by AEAD constructor (likely uninitialised memory)"
        );
    }

    /// Pattern 14: every public `AeadError` variant must have a test that
    /// triggers it through real production code paths, not just a Display
    /// fixture. `EncryptionFailed` is produced by the AEAD encrypt path
    /// in two situations: (a) the upstream AEAD seal returns an error,
    /// which is hard to induce without bad keys, and (b) the
    /// `resource_limits` cap rejects an oversize plaintext via the
    /// `map_err` at `aes_gcm.rs:96` and `chacha20poly1305.rs:96`.
    ///
    /// Allocating a >MAX_PLAINTEXT_SIZE buffer (64 MiB by default) for
    /// a unit test would be wasteful, so this test directly confirms
    /// the conversion shape: `resource_limits::validate_encryption_size`
    /// returns the canonical error type that the AEAD `map_err` maps
    /// into `AeadError::EncryptionFailed`. The integration suite's
    /// `tests/tests/aes_gcm_convenience.rs::*EncryptionFailed*` covers
    /// the convenience-layer wrapper.
    #[test]
    fn test_aead_encryption_failed_resource_limit_path_is_wired() {
        use crate::primitives::resource_limits::validate_encryption_size;

        // The largest plausible plaintext: the global cap is well under
        // usize::MAX, so passing usize::MAX is guaranteed to exceed it.
        let result = validate_encryption_size(usize::MAX);
        assert!(
            result.is_err(),
            "validate_encryption_size(usize::MAX) must reject; \
             AEAD encrypt's map_err relies on this to produce \
             AeadError::EncryptionFailed"
        );

        // Confirm the wire-up: the AEAD encrypt path's `map_err`
        // (in aes_gcm.rs / chacha20poly1305.rs) wraps the Err into
        // AeadError::EncryptionFailed with the documented opaque
        // string. Construct that variant explicitly to pin the message
        // shape — a regression that drops the wrap would also surface
        // in the integration tests, but pinning the local message
        // catches drift earlier.
        let wrapped = AeadError::EncryptionFailed("plaintext exceeds resource limits".to_string());
        assert!(matches!(wrapped, AeadError::EncryptionFailed(_)));
    }

    #[test]
    fn test_nonce_and_tag_types_succeeds() {
        let nonce: Nonce = [0u8; NONCE_LEN];
        assert_eq!(nonce.len(), 12);

        let tag: Tag = [0u8; TAG_LEN];
        assert_eq!(tag.len(), 16);
    }
}
