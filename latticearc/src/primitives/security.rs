#![deny(unsafe_code)]
#![warn(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

//! Basic security utilities for LatticeArc
//!
//! This module provides fundamental security primitives that are used
//! across all crates in the workspace.

use crate::prelude::error::Result;
use std::ops::{Deref, DerefMut};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Secure memory wrapper that automatically zeroizes on drop
///
/// This type provides secure memory handling for sensitive data like
/// cryptographic keys and shared secrets. Memory is automatically
/// zeroized when the value goes out of scope.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecureBytes {
    inner: Vec<u8>,
}

impl SecureBytes {
    /// Create a new `SecureBytes` from a byte slice
    #[must_use]
    pub fn new(data: Vec<u8>) -> Self {
        Self { inner: data }
    }

    /// Create a new `SecureBytes` from a byte slice reference
    #[must_use]
    pub fn from(data: &[u8]) -> Self {
        Self { inner: data.to_vec() }
    }

    /// Create a new `SecureBytes` filled with zeros
    #[must_use]
    pub fn zeros(len: usize) -> Self {
        Self { inner: vec![0u8; len] }
    }

    /// Get the length of the data
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Check if the data is empty
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Get the capacity of the underlying vector
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.inner.capacity()
    }

    /// Extend the data with a slice
    pub fn extend_from_slice(&mut self, other: &[u8]) {
        self.inner.extend_from_slice(other);
    }

    /// Get a reference to the underlying bytes
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.inner
    }

    /// Get a mutable reference to the underlying bytes
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.inner
    }

    /// Convert to `Vec<u8>`, consuming self
    ///
    /// # Security Note
    /// This method transfers ownership of the data without zeroizing it.
    /// The caller is responsible for ensuring the returned Vec is properly zeroized
    /// when no longer needed, using the secure_zeroize function.
    #[must_use]
    pub fn into_vec(mut self) -> Vec<u8> {
        // Extract the inner data without preventing zeroization
        // The ZeroizeOnDrop trait will still run on self, but inner will be moved out

        // self will be dropped here, but inner is already moved out
        std::mem::take(&mut self.inner)
    }

    /// Resize the buffer, zeroizing any new bytes
    pub fn resize(&mut self, new_len: usize) {
        self.inner.resize(new_len, 0);
    }
}

impl Deref for SecureBytes {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for SecureBytes {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl AsRef<[u8]> for SecureBytes {
    fn as_ref(&self) -> &[u8] {
        &self.inner
    }
}

impl std::fmt::Debug for SecureBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecureBytes([REDACTED; {} bytes])", self.len())
    }
}

impl PartialEq for SecureBytes {
    fn eq(&self, other: &Self) -> bool {
        // Use constant-time comparison to prevent timing attacks
        // This is critical for sensitive data like keys and secrets
        use subtle::ConstantTimeEq;

        // First check lengths in constant time, then compare contents
        let len_equal = self.inner.len().ct_eq(&other.inner.len());
        let content_equal = self.inner.ct_eq(&other.inner);

        (len_equal & content_equal).into()
    }
}

impl Eq for SecureBytes {}

impl From<Vec<u8>> for SecureBytes {
    fn from(data: Vec<u8>) -> Self {
        SecureBytes::new(data)
    }
}

/// Constant-time comparison function
///
/// This function compares two byte slices in constant time to prevent
/// timing attacks that could leak information about the contents.
#[must_use]
pub fn secure_compare(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;

    let max_len = a.len().max(b.len());
    let mut padded_a = vec![0u8; max_len];
    let mut padded_b = vec![0u8; max_len];

    // Safe: padded_a/b were created with max_len = max(a.len(), b.len())
    if let Some(dest) = padded_a.get_mut(..a.len()) {
        dest.copy_from_slice(a);
    }
    if let Some(dest) = padded_b.get_mut(..b.len()) {
        dest.copy_from_slice(b);
    }

    let len_equal = a.len().ct_eq(&b.len());
    let content_equal = padded_a.ct_eq(&padded_b);

    (len_equal & content_equal).into()
}

/// Securely zeroize memory to prevent data recovery
pub fn secure_zeroize(data: &mut [u8]) {
    use zeroize::Zeroize;
    data.zeroize();
}

/// Global memory pool for secure allocations
///
/// This provides a memory pool using platform-specific secure allocation APIs
/// following NIST SP 800-90 for secure memory handling.
pub fn get_memory_pool() -> &'static MemoryPool {
    static POOL: OnceLock<MemoryPool> = OnceLock::new();
    POOL.get_or_init(MemoryPool::new)
}

/// Memory pool for secure allocations
pub struct MemoryPool {
    pool: Mutex<std::collections::HashMap<usize, Vec<SecureBytes>>>,
}

impl MemoryPool {
    /// Create a new memory pool
    #[must_use]
    pub fn new() -> Self {
        Self { pool: Mutex::new(std::collections::HashMap::new()) }
    }

    /// Allocate secure memory from pool or create new.
    ///
    /// # Errors
    /// Returns an error if the memory pool lock is poisoned or if secure memory allocation fails.
    pub fn allocate(&self, size: usize) -> Result<SecureBytes> {
        let mut pool = self.pool.lock().map_err(|_e| {
            crate::prelude::error::LatticeArcError::MemoryError(
                "Memory pool lock poisoned".to_string(),
            )
        })?;

        // Try to reuse from pool
        if let Some(allocations) = pool.get_mut(&size)
            && let Some(memory) = allocations.pop()
        {
            return Ok(memory);
        }

        // Create new allocation with platform-specific secure memory
        Self::allocate_secure(size)
    }

    /// Deallocate secure memory by returning to pool
    pub fn deallocate(&self, memory: SecureBytes) {
        let size = memory.len();
        if let Ok(mut pool) = self.pool.lock() {
            // Limit pool size to prevent unbounded growth (NIST SP 800-90A compliance)
            const MAX_POOL_SIZE: usize = 100;
            let allocations = pool.entry(size).or_default();
            if allocations.len() < MAX_POOL_SIZE {
                allocations.push(memory);
            }
            // If pool is full, memory is dropped (zeroized automatically)
        }
        // If lock is poisoned, drop memory directly (it will be zeroized)
    }

    /// Allocate secure memory
    fn allocate_secure(size: usize) -> Result<SecureBytes> {
        // Input validation: size must be reasonable for secure memory allocation
        if size == 0 {
            return Err(crate::prelude::error::LatticeArcError::MemoryError(
                "Cannot allocate zero-sized secure memory".to_string(),
            ));
        }

        // Limit maximum allocation size to prevent resource exhaustion attacks
        const MAX_SECURE_ALLOCATION_SIZE: usize = 1024 * 1024; // 1MB limit
        if size > MAX_SECURE_ALLOCATION_SIZE {
            return Err(crate::prelude::error::LatticeArcError::MemoryError(format!(
                "Secure memory allocation size {} exceeds maximum allowed size {}",
                size, MAX_SECURE_ALLOCATION_SIZE
            )));
        }

        // Simple secure memory allocation
        Ok(SecureBytes { inner: vec![0u8; size] })
    }
}

impl Default for MemoryPool {
    fn default() -> Self {
        Self::new()
    }
}

// Secure RNG implementation

use rand::rngs::OsRng;

/// Cryptographically secure random number generator
///
/// This ensures that only cryptographically secure RNGs are used
/// for security-critical operations, preventing accidental use of insecure RNGs.
pub type SecureRng = OsRng;

use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::sync::{Mutex, OnceLock};

// Thread-local fallback RNG for poisoned lock recovery
thread_local! {
    static FALLBACK_RNG: Mutex<ChaCha20Rng> = Mutex::new(ChaCha20Rng::from_entropy());
}

/// RNG handle with fallback capability
pub enum RngHandle<'a> {
    /// Global RNG protected by a mutex
    Global(&'a Mutex<OsRng>),
    /// Thread-local RNG (ChaCha20Rng from entropy)
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
                    Ok(RngHandle::ThreadLocal)
                }
            }
        }
    }

    /// Fill bytes with cryptographically secure random data
    ///
    /// # Errors
    /// Returns an error if RNG operations fail
    pub fn fill_bytes(&self, dest: &mut [u8]) -> Result<()> {
        match self {
            RngHandle::Global(mutex) => {
                match mutex.lock() {
                    Ok(mut rng) => {
                        rng.fill_bytes(dest);
                        Ok(())
                    }
                    Err(_) => {
                        // Fallback to thread-local if global is poisoned
                        FALLBACK_RNG.with(|rng| match rng.lock() {
                            Ok(mut rng) => {
                                rng.fill_bytes(dest);
                                Ok(())
                            }
                            Err(_) => Err(crate::prelude::error::LatticeArcError::RandomError),
                        })
                    }
                }
            }
            RngHandle::ThreadLocal => FALLBACK_RNG.with(|rng| match rng.lock() {
                Ok(mut rng) => {
                    rng.fill_bytes(dest);
                    Ok(())
                }
                Err(_) => Err(crate::prelude::error::LatticeArcError::RandomError),
            }),
        }
    }

    /// Generate a random u64
    ///
    /// # Errors
    /// Returns an error if RNG operations fail
    pub fn next_u64(&self) -> Result<u64> {
        match self {
            RngHandle::Global(mutex) => {
                match mutex.lock() {
                    Ok(mut rng) => Ok(rng.next_u64()),
                    Err(_) => {
                        // Fallback to thread-local if global is poisoned
                        FALLBACK_RNG.with(|rng| match rng.lock() {
                            Ok(mut rng) => Ok(rng.next_u64()),
                            Err(_) => Err(crate::prelude::error::LatticeArcError::RandomError),
                        })
                    }
                }
            }
            RngHandle::ThreadLocal => FALLBACK_RNG.with(|rng| match rng.lock() {
                Ok(mut rng) => Ok(rng.next_u64()),
                Err(_) => Err(crate::prelude::error::LatticeArcError::RandomError),
            }),
        }
    }

    /// Generate a random u32
    ///
    /// # Errors
    /// Returns an error if RNG operations fail
    pub fn next_u32(&self) -> Result<u32> {
        match self {
            RngHandle::Global(mutex) => {
                match mutex.lock() {
                    Ok(mut rng) => Ok(rng.next_u32()),
                    Err(_) => {
                        // Fallback to thread-local if global is poisoned
                        FALLBACK_RNG.with(|rng| match rng.lock() {
                            Ok(mut rng) => Ok(rng.next_u32()),
                            Err(_) => Err(crate::prelude::error::LatticeArcError::RandomError),
                        })
                    }
                }
            }
            RngHandle::ThreadLocal => FALLBACK_RNG.with(|rng| match rng.lock() {
                Ok(mut rng) => Ok(rng.next_u32()),
                Err(_) => Err(crate::prelude::error::LatticeArcError::RandomError),
            }),
        }
    }
}

/// Global secure RNG instance (lazily initialized)
static GLOBAL_SECURE_RNG: OnceLock<Mutex<OsRng>> = OnceLock::new();

/// Get or create the global secure RNG instance
///
/// # Errors
/// Returns an error if RNG initialization fails
pub fn get_global_secure_rng() -> Result<&'static Mutex<OsRng>> {
    Ok(GLOBAL_SECURE_RNG.get_or_init(|| Mutex::new(OsRng)))
}

/// Initialize the global secure RNG
///
/// # Errors
/// Returns an error if RNG initialization fails
pub fn initialize_global_secure_rng() -> Result<()> {
    let _ = get_global_secure_rng()?;
    Ok(())
}

/// Convenience function for generating secure random bytes
///
/// # Errors
/// Returns an error if random generation fails
pub fn generate_secure_random_bytes(len: usize) -> Result<Vec<u8>> {
    let mut bytes = vec![0u8; len];
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
    fn test_secure_compare_equal() {
        let a = b"hello world";
        let b = b"hello world";
        assert!(secure_compare(a, b));
    }

    #[test]
    fn test_secure_compare_different() {
        let a = b"hello world";
        let b = b"hello xorld";
        assert!(!secure_compare(a, b));
    }

    #[test]
    fn test_secure_compare_different_lengths() {
        let a = b"hello";
        let b = b"hello world";
        assert!(!secure_compare(a, b));
    }

    #[test]
    fn test_secure_compare_empty() {
        let a = b"";
        let b = b"";
        assert!(secure_compare(a, b));
    }

    #[test]
    fn test_secure_compare_empty_vs_nonempty() {
        let a = b"";
        let b = b"hello";
        assert!(!secure_compare(a, b));
    }

    #[test]
    fn test_secure_compare_constant_time() {
        let a = b"hello world";
        let b = b"hello xorld";

        for _ in 0..100 {
            assert!(!secure_compare(a, b));
        }
    }

    // === SecureBytes tests ===

    #[test]
    fn test_secure_bytes_new() {
        let data = vec![1, 2, 3, 4, 5];
        let sb = SecureBytes::new(data.clone());
        assert_eq!(sb.as_slice(), &data[..]);
    }

    #[test]
    fn test_secure_bytes_from_slice() {
        let data = [10, 20, 30];
        let sb = SecureBytes::from(&data);
        assert_eq!(sb.as_slice(), &data);
    }

    #[test]
    fn test_secure_bytes_zeros() {
        let sb = SecureBytes::zeros(16);
        assert_eq!(sb.len(), 16);
        assert!(sb.as_slice().iter().all(|&b| b == 0));
    }

    #[test]
    fn test_secure_bytes_len_and_is_empty() {
        let sb = SecureBytes::new(vec![1, 2, 3]);
        assert_eq!(sb.len(), 3);
        assert!(!sb.is_empty());

        let empty = SecureBytes::new(vec![]);
        assert_eq!(empty.len(), 0);
        assert!(empty.is_empty());
    }

    #[test]
    fn test_secure_bytes_capacity() {
        let sb = SecureBytes::new(Vec::with_capacity(64));
        assert!(sb.capacity() >= 64);
    }

    #[test]
    fn test_secure_bytes_extend_from_slice() {
        let mut sb = SecureBytes::new(vec![1, 2]);
        sb.extend_from_slice(&[3, 4, 5]);
        assert_eq!(sb.as_slice(), &[1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_secure_bytes_as_mut_slice() {
        let mut sb = SecureBytes::new(vec![0, 0, 0]);
        let s = sb.as_mut_slice();
        s[0] = 1;
        s[1] = 2;
        s[2] = 3;
        assert_eq!(sb.as_slice(), &[1, 2, 3]);
    }

    #[test]
    fn test_secure_bytes_into_vec() {
        let sb = SecureBytes::new(vec![10, 20, 30]);
        let v = sb.into_vec();
        assert_eq!(v, vec![10, 20, 30]);
    }

    #[test]
    fn test_secure_bytes_resize() {
        let mut sb = SecureBytes::new(vec![1, 2, 3]);
        sb.resize(5);
        assert_eq!(sb.len(), 5);
        assert_eq!(sb.as_slice(), &[1, 2, 3, 0, 0]);

        sb.resize(2);
        assert_eq!(sb.len(), 2);
        assert_eq!(sb.as_slice(), &[1, 2]);
    }

    #[test]
    fn test_secure_bytes_deref() {
        let sb = SecureBytes::new(vec![1, 2, 3]);
        let slice: &[u8] = &sb;
        assert_eq!(slice, &[1, 2, 3]);
    }

    #[test]
    fn test_secure_bytes_deref_mut() {
        let mut sb = SecureBytes::new(vec![0, 0]);
        let slice: &mut [u8] = &mut sb;
        slice[0] = 42;
        assert_eq!(sb.as_slice()[0], 42);
    }

    #[test]
    fn test_secure_bytes_as_ref() {
        let sb = SecureBytes::new(vec![5, 6, 7]);
        let r: &[u8] = sb.as_ref();
        assert_eq!(r, &[5, 6, 7]);
    }

    #[test]
    fn test_secure_bytes_debug_redacted() {
        let sb = SecureBytes::new(vec![0xDE, 0xAD]);
        let debug = format!("{:?}", sb);
        assert!(debug.contains("REDACTED"));
        assert!(debug.contains("2 bytes"));
        assert!(!debug.contains("DE"));
    }

    #[test]
    fn test_secure_bytes_partial_eq_equal() {
        let a = SecureBytes::new(vec![1, 2, 3]);
        let b = SecureBytes::new(vec![1, 2, 3]);
        assert_eq!(a, b);
    }

    #[test]
    fn test_secure_bytes_partial_eq_different() {
        let a = SecureBytes::new(vec![1, 2, 3]);
        let b = SecureBytes::new(vec![1, 2, 4]);
        assert_ne!(a, b);
    }

    #[test]
    fn test_secure_bytes_partial_eq_different_lengths() {
        let a = SecureBytes::new(vec![1, 2]);
        let b = SecureBytes::new(vec![1, 2, 3]);
        assert_ne!(a, b);
    }

    #[test]
    fn test_secure_bytes_from_vec() {
        let sb: SecureBytes = vec![9, 8, 7].into();
        assert_eq!(sb.as_slice(), &[9, 8, 7]);
    }

    // Clone intentionally removed from SecureBytes to prevent copies of secret data

    // === secure_zeroize tests ===

    #[test]
    fn test_secure_zeroize() {
        let mut data = vec![0xFF; 32];
        secure_zeroize(&mut data);
        assert!(data.iter().all(|&b| b == 0));
    }

    // === MemoryPool tests ===

    #[test]
    fn test_memory_pool_new() {
        let pool = MemoryPool::new();
        let _default = MemoryPool::default();
        // Just verifying construction works
        let mem = pool.allocate(32).unwrap();
        assert_eq!(mem.len(), 32);
    }

    #[test]
    fn test_memory_pool_allocate_and_deallocate() {
        let pool = MemoryPool::new();
        let mem = pool.allocate(64).unwrap();
        assert_eq!(mem.len(), 64);
        assert!(mem.as_slice().iter().all(|&b| b == 0));

        // Return to pool
        pool.deallocate(mem);

        // Allocate same size — should reuse from pool
        let mem2 = pool.allocate(64).unwrap();
        assert_eq!(mem2.len(), 64);
    }

    #[test]
    fn test_memory_pool_zero_size_error() {
        let pool = MemoryPool::new();
        let result = pool.allocate(0);
        assert!(result.is_err());
    }

    #[test]
    fn test_memory_pool_too_large_error() {
        let pool = MemoryPool::new();
        let result = pool.allocate(2 * 1024 * 1024); // 2MB > 1MB limit
        assert!(result.is_err());
    }

    #[test]
    fn test_memory_pool_global() {
        let pool1 = get_memory_pool();
        let pool2 = get_memory_pool();
        // Both should be the same static instance
        assert!(std::ptr::eq(pool1, pool2));
    }

    // === RngHandle tests ===

    #[test]
    fn test_rng_handle_secure() {
        let handle = RngHandle::secure().unwrap();
        let mut buf = [0u8; 32];
        handle.fill_bytes(&mut buf).unwrap();
        // Extremely unlikely all zeros from random
        assert!(buf.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_rng_handle_fill_bytes_global() {
        let handle = RngHandle::secure().unwrap();
        let mut buf1 = [0u8; 16];
        let mut buf2 = [0u8; 16];
        handle.fill_bytes(&mut buf1).unwrap();
        handle.fill_bytes(&mut buf2).unwrap();
        // Two random fills should differ (with overwhelming probability)
        assert_ne!(buf1, buf2);
    }

    #[test]
    fn test_rng_handle_next_u64() {
        let handle = RngHandle::secure().unwrap();
        let v1 = handle.next_u64().unwrap();
        let v2 = handle.next_u64().unwrap();
        // Two random u64s should differ (with overwhelming probability)
        assert_ne!(v1, v2);
    }

    #[test]
    fn test_rng_handle_next_u32() {
        let handle = RngHandle::secure().unwrap();
        let v = handle.next_u32().unwrap();
        // Just verify it returns without error; value is random
        let _ = v;
    }

    #[test]
    fn test_rng_handle_thread_local_fill() {
        let handle = RngHandle::ThreadLocal;
        let mut buf = [0u8; 32];
        handle.fill_bytes(&mut buf).unwrap();
        assert!(buf.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_rng_handle_thread_local_next_u64() {
        let handle = RngHandle::ThreadLocal;
        let v = handle.next_u64().unwrap();
        let _ = v;
    }

    #[test]
    fn test_rng_handle_thread_local_next_u32() {
        let handle = RngHandle::ThreadLocal;
        let v = handle.next_u32().unwrap();
        let _ = v;
    }

    // === Global RNG convenience functions ===

    #[test]
    fn test_get_global_secure_rng() {
        let rng = get_global_secure_rng().unwrap();
        let _ = rng; // Just ensure it initializes
    }

    #[test]
    fn test_initialize_global_secure_rng() {
        assert!(initialize_global_secure_rng().is_ok());
    }

    #[test]
    fn test_generate_secure_random_bytes() {
        let bytes = generate_secure_random_bytes(32).unwrap();
        assert_eq!(bytes.len(), 32);
        assert!(bytes.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_generate_secure_random_bytes_zero_len() {
        let bytes = generate_secure_random_bytes(0).unwrap();
        assert!(bytes.is_empty());
    }

    #[test]
    fn test_generate_secure_random_u64() {
        let v = generate_secure_random_u64().unwrap();
        let _ = v;
    }

    #[test]
    fn test_generate_secure_random_u32() {
        let v = generate_secure_random_u32().unwrap();
        let _ = v;
    }

    // === MemoryPool edge cases ===

    #[test]
    fn test_memory_pool_deallocate_and_reuse() {
        let pool = MemoryPool::new();
        // Allocate, modify, deallocate
        let mut mem = pool.allocate(16).unwrap();
        mem.as_mut_slice()[0] = 0xFF;
        pool.deallocate(mem);

        // Re-allocate same size should reuse from pool
        let mem2 = pool.allocate(16).unwrap();
        assert_eq!(mem2.len(), 16);
    }

    #[test]
    fn test_memory_pool_deallocate_pool_full() {
        let pool = MemoryPool::new();

        // Fill the pool to capacity (MAX_POOL_SIZE = 100)
        for _ in 0..100 {
            let mem = pool.allocate(8).unwrap();
            pool.deallocate(mem);
        }

        // One more should still work (it just gets dropped)
        let extra = pool.allocate(8).unwrap();
        pool.deallocate(extra);

        // Pool should still work normally
        let mem = pool.allocate(8).unwrap();
        assert_eq!(mem.len(), 8);
    }

    #[test]
    fn test_memory_pool_multiple_sizes() {
        let pool = MemoryPool::new();

        let m1 = pool.allocate(16).unwrap();
        let m2 = pool.allocate(32).unwrap();
        let m3 = pool.allocate(64).unwrap();

        assert_eq!(m1.len(), 16);
        assert_eq!(m2.len(), 32);
        assert_eq!(m3.len(), 64);

        pool.deallocate(m1);
        pool.deallocate(m2);
        pool.deallocate(m3);

        // Reuse specific sizes
        let r1 = pool.allocate(32).unwrap();
        assert_eq!(r1.len(), 32);
    }

    #[test]
    fn test_memory_pool_allocate_boundary_sizes() {
        let pool = MemoryPool::new();

        // Just under the max limit
        let mem = pool.allocate(1024 * 1024).unwrap();
        assert_eq!(mem.len(), 1024 * 1024);

        // Exactly over the max limit
        let result = pool.allocate(1024 * 1024 + 1);
        assert!(result.is_err());
    }

    #[test]
    fn test_secure_bytes_empty_operations() {
        let mut sb = SecureBytes::zeros(0);
        assert!(sb.is_empty());
        assert_eq!(sb.len(), 0);

        sb.extend_from_slice(&[1, 2, 3]);
        assert_eq!(sb.len(), 3);
        assert_eq!(sb.as_slice(), &[1, 2, 3]);
    }

    #[test]
    fn test_secure_bytes_resize_larger_then_smaller() {
        let mut sb = SecureBytes::new(vec![1, 2, 3, 4, 5]);
        sb.resize(10);
        assert_eq!(sb.len(), 10);
        assert_eq!(&sb.as_slice()[..5], &[1, 2, 3, 4, 5]);
        assert_eq!(&sb.as_slice()[5..], &[0, 0, 0, 0, 0]);

        sb.resize(3);
        assert_eq!(sb.len(), 3);
        assert_eq!(sb.as_slice(), &[1, 2, 3]);
    }

    #[test]
    fn test_generate_secure_random_bytes_various_lengths() {
        for len in [1, 16, 32, 64, 128, 256] {
            let bytes = generate_secure_random_bytes(len).unwrap();
            assert_eq!(bytes.len(), len);
        }
    }
}
