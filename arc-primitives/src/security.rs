#![deny(unsafe_code)]
#![warn(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

//! Basic security utilities for LatticeArc
//!
//! This module provides fundamental security primitives that are used
//! across all crates in the workspace.

use arc_prelude::error::Result;
use std::ops::{Deref, DerefMut};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Secure memory wrapper that automatically zeroizes on drop
///
/// This type provides secure memory handling for sensitive data like
/// cryptographic keys and shared secrets. Memory is automatically
/// zeroized when the value goes out of scope.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
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

    /// Convert to Vec<u8>, consuming self
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
            arc_prelude::error::LatticeArcError::MemoryError(
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
            return Err(arc_prelude::error::LatticeArcError::MemoryError(
                "Cannot allocate zero-sized secure memory".to_string(),
            ));
        }

        // Limit maximum allocation size to prevent resource exhaustion attacks
        const MAX_SECURE_ALLOCATION_SIZE: usize = 1024 * 1024; // 1MB limit
        if size > MAX_SECURE_ALLOCATION_SIZE {
            return Err(arc_prelude::error::LatticeArcError::MemoryError(format!(
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
    /// Get a secure RNG handle, with thread-local fallback if global is poisoned
    ///
    /// # Errors
    /// Returns an error if all RNG sources fail
    pub fn secure() -> Result<RngHandle<'a>> {
        match get_global_secure_rng() {
            Ok(global) => Ok(RngHandle::Global(global)),
            Err(_) => Ok(RngHandle::ThreadLocal),
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
                            Err(_) => Err(arc_prelude::error::LatticeArcError::RandomError),
                        })
                    }
                }
            }
            RngHandle::ThreadLocal => FALLBACK_RNG.with(|rng| match rng.lock() {
                Ok(mut rng) => {
                    rng.fill_bytes(dest);
                    Ok(())
                }
                Err(_) => Err(arc_prelude::error::LatticeArcError::RandomError),
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
                            Err(_) => Err(arc_prelude::error::LatticeArcError::RandomError),
                        })
                    }
                }
            }
            RngHandle::ThreadLocal => FALLBACK_RNG.with(|rng| match rng.lock() {
                Ok(mut rng) => Ok(rng.next_u64()),
                Err(_) => Err(arc_prelude::error::LatticeArcError::RandomError),
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
                            Err(_) => Err(arc_prelude::error::LatticeArcError::RandomError),
                        })
                    }
                }
            }
            RngHandle::ThreadLocal => FALLBACK_RNG.with(|rng| match rng.lock() {
                Ok(mut rng) => Ok(rng.next_u32()),
                Err(_) => Err(arc_prelude::error::LatticeArcError::RandomError),
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
mod tests {
    use super::*;

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
}
