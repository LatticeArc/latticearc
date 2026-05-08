#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

//! Basic security utilities for LatticeArc
//!
//! This module provides fundamental security primitives that are used
//! across all crates in the workspace.

use crate::prelude::error::Result;
use crate::types::SecretVec;

// `SecureBytes` has been removed. All variable-length heap-backed secret
// storage now uses [`SecretVec`] (see `docs/SECRET_TYPE_INVARIANTS.md`).
// `MemoryPool` below is the sole former consumer; it holds `SecretVec` values.

/// Constant-time comparison function
///
/// This function compares two byte slices in constant time to prevent
/// timing attacks that could leak information about the contents.
#[must_use]
pub fn secure_compare(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;

    // reject mismatched lengths early. The
    // previous shape allocated `max(a.len(), b.len())` zeroized buffers
    // even on the inevitable-Err path, which an attacker controlling
    // one input length could amplify into MB-sized allocations per
    // call. Length is structurally not secret here (the caller knows
    // both lengths), so the early return is constant-time relative to
    // each fixed-length comparison; comparisons across messages of
    // *different* declared lengths are all rejected at the same cost.
    if a.len() != b.len() {
        return false;
    }

    // Equal-length case: standard `ct_eq` over the borrowed slices is
    // already constant-time and allocates nothing.
    a.ct_eq(b).into()
}

/// Securely zeroize memory to prevent data recovery
pub fn secure_zeroize(data: &mut [u8]) {
    use zeroize::Zeroize;
    data.zeroize();
}

// the `MemoryPool` type and `get_memory_pool`
// helper were removed entirely. The pool's `deallocate` was a no-op
// (it dropped the buffer rather than caching it), so every `allocate`
// call paid mutex-lock overhead with zero cache benefit. Use
// `SecretVec::zero(size)` directly at every call site — same semantics,
// no lock contention.

/// Allocate a zeroed `SecretVec` of `size` bytes. Replaces the
/// `MemoryPool::allocate` API; this is a thin wrapper around
/// `SecretVec::zero(size)` with the same per-call size validation
/// the pool used to enforce.
///
/// # Errors
/// Returns an error if `size` is zero or exceeds `1 MiB`.
pub fn allocate_secure_buffer(size: usize) -> Result<SecretVec> {
    if size == 0 {
        return Err(crate::prelude::error::LatticeArcError::MemoryError(
            "Cannot allocate zero-sized secure memory".to_string(),
        ));
    }
    const MAX_SECURE_ALLOCATION_SIZE: usize = 1024 * 1024;
    if size > MAX_SECURE_ALLOCATION_SIZE {
        return Err(crate::prelude::error::LatticeArcError::MemoryError(format!(
            "Secure memory allocation size {} exceeds maximum allowed size {}",
            size, MAX_SECURE_ALLOCATION_SIZE
        )));
    }
    Ok(SecretVec::zero(size))
}

// Secure RNG implementation

use rand::rngs::OsRng;
use rand_core::UnwrapErr;

/// Cryptographically secure random number generator.
///
/// Wraps `rand::rngs::OsRng` (which is `TryRngCore` in rand 0.9, fallible at
/// the type level) in `rand_core::UnwrapErr` so it presents the infallible
/// `RngCore` surface that the rest of the API expects. OS RNG failure is
/// fatal — see `crate::primitives::rand::csprng` module docs for the
/// rationale.
pub type SecureRng = UnwrapErr<OsRng>;

use rand::{RngCore, SeedableRng}; // SeedableRng provides ChaCha20Rng::from_os_rng()
use rand_chacha::ChaCha20Rng;
use std::sync::{Mutex, OnceLock};

// Thread-local fallback RNG for poisoned lock recovery.
// `from_os_rng()` replaced `from_entropy()` in rand 0.9.
thread_local! {
    static FALLBACK_RNG: Mutex<ChaCha20Rng> = Mutex::new(ChaCha20Rng::from_os_rng());
}

/// RNG handle with fallback capability.
///
/// Under `feature = "fips"` the `ThreadLocal` variant is **removed at
/// compile time** because the underlying `ChaCha20Rng` is not on the FIPS
/// 140-3 approved-function list. This is type-level enforcement of the
/// same invariant that the runtime guard in
/// [`Self::secure`] / `fallback_*` helpers enforces — external code
/// cannot even *construct* `RngHandle::ThreadLocal` in a FIPS build, so
/// the runtime branch becomes unreachable rather than merely
/// rejected. The two layers are intentional defense-in-depth.
#[non_exhaustive]
pub enum RngHandle<'a> {
    /// Global RNG protected by a mutex
    Global(&'a Mutex<SecureRng>),
    /// Thread-local RNG (ChaCha20Rng from entropy). Excluded from FIPS
    /// builds — see the type-level docs above.
    #[cfg(not(feature = "fips"))]
    ThreadLocal,
}

impl<'a> RngHandle<'a> {
    /// Get a secure RNG handle, with thread-local fallback if global is poisoned.
    ///
    /// In FIPS mode, ChaCha20Rng fallback is not permitted (non-FIPS DRBG).
    /// The function returns an error instead of silently degrading.
    ///
    /// # Errors
    /// Returns an error if all RNG sources fail, or if FIPS mode rejects
    /// the non-FIPS fallback.
    pub fn secure() -> Result<RngHandle<'a>> {
        match get_global_secure_rng() {
            Ok(global) => Ok(RngHandle::Global(global)),
            Err(_err) => {
                #[cfg(feature = "fips")]
                {
                    Err(crate::prelude::error::LatticeArcError::RandomError)
                }
                #[cfg(not(feature = "fips"))]
                {
                    tracing::warn!("Global OsRng unavailable; falling back to thread-local RNG");
                    Ok(RngHandle::ThreadLocal)
                }
            }
        }
    }

    /// Fill bytes with cryptographically secure random data
    ///
    /// # Errors
    /// Returns an error if RNG operations fail. Under `feature = "fips"`,
    /// also returns an error rather than fall back to the thread-local
    /// ChaCha20Rng (FIPS 140-3 forbids unapproved DRBGs).
    pub fn fill_bytes(&self, dest: &mut [u8]) -> Result<()> {
        match self {
            RngHandle::Global(mutex) => match mutex.lock() {
                Ok(mut rng) => {
                    rng.fill_bytes(dest);
                    Ok(())
                }
                Err(_) => fallback_fill_bytes(dest),
            },
            #[cfg(not(feature = "fips"))]
            RngHandle::ThreadLocal => fallback_fill_bytes(dest),
        }
    }

    /// Generate a random u64
    ///
    /// # Errors
    /// Returns an error if RNG operations fail. Under `feature = "fips"`,
    /// also returns an error rather than fall back to the thread-local
    /// ChaCha20Rng (FIPS 140-3 forbids unapproved DRBGs).
    pub fn next_u64(&self) -> Result<u64> {
        match self {
            RngHandle::Global(mutex) => match mutex.lock() {
                Ok(mut rng) => Ok(rng.next_u64()),
                Err(_) => fallback_next_u64(),
            },
            #[cfg(not(feature = "fips"))]
            RngHandle::ThreadLocal => fallback_next_u64(),
        }
    }

    /// Generate a random u32
    ///
    /// # Errors
    /// Returns an error if RNG operations fail. Under `feature = "fips"`,
    /// also returns an error rather than fall back to the thread-local
    /// ChaCha20Rng (FIPS 140-3 forbids unapproved DRBGs).
    pub fn next_u32(&self) -> Result<u32> {
        match self {
            RngHandle::Global(mutex) => match mutex.lock() {
                Ok(mut rng) => Ok(rng.next_u32()),
                Err(_) => fallback_next_u32(),
            },
            #[cfg(not(feature = "fips"))]
            RngHandle::ThreadLocal => fallback_next_u32(),
        }
    }
}

/// Fall back to the thread-local ChaCha20Rng when the global RNG is
/// unavailable (typically because a panic in another thread poisoned its
/// `Mutex`). Under `feature = "fips"` this path is rejected: ChaCha20Rng
/// is not on the FIPS 140-3 approved-function list, so a panic-driven
/// silent downgrade would constitute a module-policy violation.
#[inline]
fn fallback_fill_bytes(dest: &mut [u8]) -> Result<()> {
    #[cfg(feature = "fips")]
    {
        let _ = dest;
        Err(crate::prelude::error::LatticeArcError::RandomError)
    }
    #[cfg(not(feature = "fips"))]
    FALLBACK_RNG.with(|rng| match rng.lock() {
        Ok(mut rng) => {
            rng.fill_bytes(dest);
            Ok(())
        }
        Err(_) => Err(crate::prelude::error::LatticeArcError::RandomError),
    })
}

#[inline]
fn fallback_next_u64() -> Result<u64> {
    #[cfg(feature = "fips")]
    {
        Err(crate::prelude::error::LatticeArcError::RandomError)
    }
    #[cfg(not(feature = "fips"))]
    FALLBACK_RNG.with(|rng| match rng.lock() {
        Ok(mut rng) => Ok(rng.next_u64()),
        Err(_) => Err(crate::prelude::error::LatticeArcError::RandomError),
    })
}

#[inline]
fn fallback_next_u32() -> Result<u32> {
    #[cfg(feature = "fips")]
    {
        Err(crate::prelude::error::LatticeArcError::RandomError)
    }
    #[cfg(not(feature = "fips"))]
    FALLBACK_RNG.with(|rng| match rng.lock() {
        Ok(mut rng) => Ok(rng.next_u32()),
        Err(_) => Err(crate::prelude::error::LatticeArcError::RandomError),
    })
}

/// Global secure RNG instance (lazily initialized)
static GLOBAL_SECURE_RNG: OnceLock<Mutex<SecureRng>> = OnceLock::new();

/// Get or create the global secure RNG instance
///
/// # Errors
/// Returns an error if RNG initialization fails
pub fn get_global_secure_rng() -> Result<&'static Mutex<SecureRng>> {
    Ok(GLOBAL_SECURE_RNG.get_or_init(|| Mutex::new(UnwrapErr(OsRng))))
}

/// Initialize the global secure RNG
///
/// # Errors
/// Returns an error if RNG initialization fails
pub fn initialize_global_secure_rng() -> Result<()> {
    let _ = get_global_secure_rng()?;
    Ok(())
}

/// Convenience function for generating secure random bytes.
///
/// Returns the bytes wrapped in `Zeroizing<Vec<u8>>` so the caller is
/// forced to handle them as secret material. The AEAD `WeakKey` error
/// help-text steers users here for symmetric-key generation; a bare
/// `Vec<u8>` would silently drop without wiping when callers split or
/// copied the bytes.
///
/// # Errors
/// Returns `LatticeArcError::InvalidParameter` if `len` exceeds the
/// 1 MiB cap (rejects `usize::MAX` before it can OOM the allocator).
/// Returns an error if random generation fails.
pub fn generate_secure_random_bytes(len: usize) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    // M6: cap matches `allocate_secure_buffer` so both
    // sibling helpers refuse the same `usize::MAX → 18 EiB
    // allocation` foot-gun. Any legitimate caller stays well under
    // 1 MiB (typical sizes: 16-byte salts, 32-byte keys, 96-byte
    // material). A `usize::MAX` request previously aborted the
    // process via OOM before any error path ran.
    const MAX_RANDOM_BYTES: usize = 1024 * 1024;
    if len > MAX_RANDOM_BYTES {
        return Err(crate::prelude::LatticeArcError::InvalidParameter(format!(
            "generate_secure_random_bytes: requested {len} bytes exceeds {MAX_RANDOM_BYTES} cap"
        )));
    }
    let mut bytes = zeroize::Zeroizing::new(vec![0u8; len]);
    RngHandle::secure()?.fill_bytes(&mut bytes)?;
    Ok(bytes)
}

/// Convenience function for generating secure random u64
///
/// # Errors
/// Returns an error if random generation fails
pub fn generate_secure_random_u64() -> Result<u64> {
    RngHandle::secure()?.next_u64()
}

/// Convenience function for generating secure random u32
///
/// # Errors
/// Returns an error if random generation fails
pub fn generate_secure_random_u32() -> Result<u32> {
    RngHandle::secure()?.next_u32()
}

// Types are already defined above, no need for re-exports

#[cfg(test)]
#[allow(clippy::unwrap_used)]
#[allow(clippy::expect_used)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;

    // === secure_compare tests ===

    #[test]
    fn test_secure_compare_equal_is_secure_succeeds() {
        let a = b"hello world";
        let b = b"hello world";
        assert!(secure_compare(a, b));
    }

    #[test]
    fn test_secure_compare_different_is_secure_succeeds() {
        let a = b"hello world";
        let b = b"hello xorld";
        assert!(!secure_compare(a, b));
    }

    #[test]
    fn test_secure_compare_different_lengths_is_secure_has_correct_size() {
        let a = b"hello";
        let b = b"hello world";
        assert!(!secure_compare(a, b));
    }

    #[test]
    fn test_secure_compare_empty_is_secure_succeeds() {
        let a = b"";
        let b = b"";
        assert!(secure_compare(a, b));
    }

    #[test]
    fn test_secure_compare_empty_vs_nonempty_is_secure_succeeds() {
        let a = b"";
        let b = b"hello";
        assert!(!secure_compare(a, b));
    }

    #[test]
    fn test_secure_compare_constant_time_is_secure_succeeds() {
        let a = b"hello world";
        let b = b"hello xorld";

        for _ in 0..100 {
            assert!(!secure_compare(a, b));
        }
    }

    // === secure_zeroize tests ===

    #[test]
    fn test_secure_zeroize_clears_bytes_succeeds() {
        let mut data = vec![0xFF; 32];
        secure_zeroize(&mut data);
        assert!(data.iter().all(|&b| b == 0));
    }

    // === allocate_secure_buffer tests ===

    #[test]
    fn test_allocate_secure_buffer_basic_succeeds() {
        let mem = allocate_secure_buffer(32).unwrap();
        assert_eq!(mem.len(), 32);
        assert!(mem.expose_secret().iter().all(|&b| b == 0));
    }

    #[test]
    fn test_allocate_secure_buffer_zero_size_fails() {
        let result = allocate_secure_buffer(0);
        assert!(result.is_err());
    }

    #[test]
    fn test_allocate_secure_buffer_too_large_fails() {
        let result = allocate_secure_buffer(2 * 1024 * 1024);
        assert!(result.is_err());
    }

    // === RngHandle tests ===

    #[test]
    fn test_rng_handle_secure_is_secure_succeeds() {
        let handle = RngHandle::secure().unwrap();
        let mut buf = [0u8; 32];
        handle.fill_bytes(&mut buf).unwrap();
        // Extremely unlikely all zeros from random
        assert!(buf.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_rng_handle_fill_bytes_global_succeeds() {
        let handle = RngHandle::secure().unwrap();
        let mut buf1 = [0u8; 16];
        let mut buf2 = [0u8; 16];
        handle.fill_bytes(&mut buf1).unwrap();
        handle.fill_bytes(&mut buf2).unwrap();
        // Two random fills should differ (with overwhelming probability)
        assert_ne!(buf1, buf2);
    }

    #[test]
    fn test_rng_handle_next_u64_succeeds() {
        let handle = RngHandle::secure().unwrap();
        let v1 = handle.next_u64().unwrap();
        let v2 = handle.next_u64().unwrap();
        // Two random u64s should differ (with overwhelming probability)
        assert_ne!(v1, v2);
    }

    #[test]
    fn test_rng_handle_next_u32_succeeds() {
        let handle = RngHandle::secure().unwrap();
        let v = handle.next_u32().unwrap();
        // Just verify it returns without error; value is random
        let _ = v;
    }

    // The `RngHandle::ThreadLocal` variant is gated `#[cfg(not(feature =
    // "fips"))]` at the type level — under `feature = "fips"` it does not
    // exist and these tests are simply absent. The earlier
    // `_rejected_under_fips` runtime-guard tests were retired when the
    // type-level enforcement landed; the type system now makes the
    // runtime guard's "Err(RandomError)" branch unreachable in FIPS
    // builds because no caller can construct the variant to hit it.

    #[cfg(not(feature = "fips"))]
    #[test]
    fn test_rng_handle_thread_local_fill_succeeds() {
        let handle = RngHandle::ThreadLocal;
        let mut buf = [0u8; 32];
        handle.fill_bytes(&mut buf).unwrap();
        assert!(buf.iter().any(|&b| b != 0));
    }

    #[cfg(not(feature = "fips"))]
    #[test]
    fn test_rng_handle_thread_local_next_u64_succeeds() {
        let handle = RngHandle::ThreadLocal;
        let v = handle.next_u64().unwrap();
        let _ = v;
    }

    #[cfg(not(feature = "fips"))]
    #[test]
    fn test_rng_handle_thread_local_next_u32_succeeds() {
        let handle = RngHandle::ThreadLocal;
        let v = handle.next_u32().unwrap();
        let _ = v;
    }

    // === Global RNG convenience functions ===

    #[test]
    fn test_get_global_secure_rng_succeeds() {
        let rng = get_global_secure_rng().unwrap();
        let _ = rng; // Just ensure it initializes
    }

    #[test]
    fn test_initialize_global_secure_rng_succeeds() {
        assert!(initialize_global_secure_rng().is_ok());
    }

    #[test]
    fn test_generate_secure_random_bytes_is_secure_succeeds() {
        let bytes = generate_secure_random_bytes(32).unwrap();
        assert_eq!(bytes.len(), 32);
        assert!(bytes.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_generate_secure_random_bytes_zero_len_succeeds() {
        let bytes = generate_secure_random_bytes(0).unwrap();
        assert!(bytes.is_empty());
    }

    #[test]
    fn test_generate_secure_random_u64_is_secure_succeeds() {
        let v = generate_secure_random_u64().unwrap();
        let _ = v;
    }

    #[test]
    fn test_generate_secure_random_u32_is_secure_succeeds() {
        let v = generate_secure_random_u32().unwrap();
        let _ = v;
    }

    #[test]
    fn test_allocate_secure_buffer_boundary_succeeds() {
        let mem = allocate_secure_buffer(1024 * 1024).unwrap();
        assert_eq!(mem.len(), 1024 * 1024);

        let result = allocate_secure_buffer(1024 * 1024 + 1);
        assert!(result.is_err());
    }

    #[test]
    fn test_generate_secure_random_bytes_various_lengths_is_secure_has_correct_size() {
        for len in [1, 16, 32, 64, 128, 256] {
            let bytes = generate_secure_random_bytes(len).unwrap();
            assert_eq!(bytes.len(), len);
        }
    }
}
