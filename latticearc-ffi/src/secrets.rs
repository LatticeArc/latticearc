//! Opaque secret buffers.
//!
//! Every secret the library produces (derived keys, unwrapped keys, shared
//! secrets) comes back as a [`SecretBytes`] handle. The bytes stay in Rust
//! memory, zeroized on drop and locked against swapping where the OS allows
//! it. They only cross the language boundary through the explicitly named
//! [`SecretBytes::export_bytes`].

use std::sync::Arc;

use latticearc::SecretVec;
use latticearc::primitives::rand::secure_rng;
use rand::Rng;
use zeroize::Zeroizing;

use crate::error::LatticeArcError;

/// Largest buffer [`SecretBytes::random`] will allocate: enough for any key,
/// seed or salt, small enough that a bad `len` cannot exhaust memory.
pub const MAX_RANDOM_LEN: u32 = 4096;

/// A secret byte string held in Rust memory.
#[derive(uniffi::Object)]
pub struct SecretBytes {
    inner: SecretVec,
}

#[uniffi::export]
impl SecretBytes {
    /// Wraps bytes the caller already holds (a password, a stored seed).
    ///
    /// The caller's own copy is not zeroized; clear it as soon as this
    /// returns.
    #[uniffi::constructor]
    #[must_use]
    pub fn import(bytes: Vec<u8>) -> Arc<Self> {
        Self::from_vec(bytes)
    }

    /// Fills a fresh buffer of `len` bytes from the OS CSPRNG.
    ///
    /// # Errors
    ///
    /// `InvalidInput` when `len` is zero or above [`MAX_RANDOM_LEN`].
    #[uniffi::constructor]
    pub fn random(len: u32) -> Result<Arc<Self>, LatticeArcError> {
        if len == 0 || len > MAX_RANDOM_LEN {
            return Err(LatticeArcError::invalid_input(format!(
                "random length must be 1..={MAX_RANDOM_LEN}, got {len}"
            )));
        }
        let mut bytes = Zeroizing::new(vec![0u8; len as usize]);
        secure_rng().fill_bytes(&mut bytes);
        Ok(Self::from_vec(take_zeroizing(bytes)))
    }

    /// Number of bytes held.
    #[must_use]
    pub fn len(&self) -> u32 {
        u32::try_from(self.inner.len()).unwrap_or(u32::MAX)
    }

    /// `true` when the buffer holds no bytes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.len() == 0
    }

    /// `true` when every page of this buffer is locked in RAM (`mlock`).
    /// Always `false` when the library was built without `secret-mlock`.
    #[must_use]
    pub fn is_locked(&self) -> bool {
        self.inner.is_locked()
    }

    /// Copies the secret out. This is the only way secret material leaves
    /// Rust; the copy is the caller's responsibility to clear.
    #[must_use]
    pub fn export_bytes(&self) -> Vec<u8> {
        self.inner.expose_secret().to_vec()
    }
}

/// Redacted: prints the length, never the bytes.
impl std::fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretBytes").field("len", &self.inner.len()).finish_non_exhaustive()
    }
}

impl SecretBytes {
    pub(crate) fn from_vec(bytes: Vec<u8>) -> Arc<Self> {
        Arc::new(Self { inner: SecretVec::new(bytes) })
    }

    pub(crate) fn expose(&self) -> &[u8] {
        self.inner.expose_secret()
    }

    /// Borrows the secret as a 32-byte array, for the AEAD and KDF keys that
    /// are fixed at that size.
    pub(crate) fn key32(&self, what: &str) -> Result<Zeroizing<[u8; 32]>, LatticeArcError> {
        let bytes = self.expose();
        let arr: [u8; 32] = bytes.try_into().map_err(|_e| {
            LatticeArcError::invalid_input(format!("{what} must be 32 bytes, got {}", bytes.len()))
        })?;
        Ok(Zeroizing::new(arr))
    }
}

/// Moves the vector out of a `Zeroizing` wrapper without copying it. The
/// wrapper is left holding an empty vector, so nothing secret remains in it.
pub(crate) fn take_zeroizing(mut z: Zeroizing<Vec<u8>>) -> Vec<u8> {
    std::mem::take(&mut *z)
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "Tests use unwrap for simplicity")]
mod tests {
    use super::*;

    #[test]
    fn import_export_roundtrip() {
        let s = SecretBytes::import(vec![1, 2, 3]);
        assert_eq!(s.len(), 3);
        assert!(!s.is_empty());
        assert_eq!(s.export_bytes(), vec![1, 2, 3]);
    }

    #[test]
    fn random_rejects_zero_and_oversized() {
        assert!(matches!(SecretBytes::random(0), Err(LatticeArcError::InvalidInput { .. })));
        assert!(matches!(
            SecretBytes::random(MAX_RANDOM_LEN + 1),
            Err(LatticeArcError::InvalidInput { .. })
        ));
    }

    #[test]
    fn random_differs_between_calls() {
        let a = SecretBytes::random(32).unwrap();
        let b = SecretBytes::random(32).unwrap();
        assert_eq!(a.len(), 32);
        assert_ne!(a.export_bytes(), b.export_bytes());
    }

    #[test]
    fn key32_requires_exact_length() {
        let short = SecretBytes::import(vec![0u8; 16]);
        assert!(matches!(short.key32("kek"), Err(LatticeArcError::InvalidInput { .. })));
        let ok = SecretBytes::import(vec![7u8; 32]);
        assert_eq!(*ok.key32("kek").unwrap(), [7u8; 32]);
    }

    #[test]
    fn debug_output_redacts_contents() {
        let s = SecretBytes::import(vec![0xAB; 8]);
        let text = format!("{s:?}");
        assert!(text.contains("len: 8"));
        assert!(!text.contains("171") && !text.contains("ab"));
    }

    #[test]
    fn take_zeroizing_moves_without_copy() {
        let z = Zeroizing::new(vec![9u8; 4]);
        let v = take_zeroizing(z);
        assert_eq!(v, vec![9u8; 4]);
    }
}
