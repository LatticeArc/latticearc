#![deny(unsafe_code)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::panic)]
#![allow(clippy::indexing_slicing)]
#![allow(clippy::cast_possible_truncation)]
#![allow(missing_docs)]

//! Coverage tests for security.rs
//!
//! Targets MemoryPool, RngHandle, and convenience RNG functions.
//! (The former `SecureBytes` type has been removed; variable-length heap
//! secret storage now lives in `types::SecretVec` and is tested there.)

use latticearc::primitives::security::{
    MemoryPool, RngHandle, generate_secure_random_bytes, generate_secure_random_u32,
    generate_secure_random_u64, get_global_secure_rng, get_memory_pool,
    initialize_global_secure_rng, secure_compare, secure_zeroize,
};

// ============================================================================
// secure_compare tests
// ============================================================================

#[test]
fn test_secure_compare_equal_slices_succeeds() {
    assert!(secure_compare(b"hello", b"hello"));
}

#[test]
fn test_secure_compare_different_content_succeeds() {
    assert!(!secure_compare(b"hello", b"world"));
}

#[test]
fn test_secure_compare_different_lengths_has_correct_size() {
    assert!(!secure_compare(b"hello", b"hi"));
}

#[test]
fn test_secure_compare_empty_succeeds() {
    assert!(secure_compare(b"", b""));
}

#[test]
fn test_secure_compare_one_empty_succeeds() {
    assert!(!secure_compare(b"", b"a"));
    assert!(!secure_compare(b"a", b""));
}

// ============================================================================
// secure_zeroize tests
// ============================================================================

#[test]
fn test_secure_zeroize_succeeds() {
    let mut data = vec![0xFFu8; 32];
    secure_zeroize(&mut data);
    assert!(data.iter().all(|&b| b == 0));
}

// ============================================================================
// MemoryPool tests
// ============================================================================

#[test]
fn test_memory_pool_new_succeeds() {
    let pool = MemoryPool::new();
    let mem = pool.allocate(64).unwrap();
    assert_eq!(mem.len(), 64);
    assert!(mem.expose_secret().iter().all(|&b| b == 0));
}

#[test]
fn test_memory_pool_default_succeeds() {
    let pool = MemoryPool::default();
    let mem = pool.allocate(32).unwrap();
    assert_eq!(mem.len(), 32);
}

#[test]
fn test_memory_pool_allocate_reuse_succeeds() {
    let pool = MemoryPool::new();

    // Allocate and deallocate
    let mem1 = pool.allocate(64).unwrap();
    pool.deallocate(mem1);

    // Next allocation of same size should reuse from pool
    let mem2 = pool.allocate(64).unwrap();
    assert_eq!(mem2.len(), 64);
}

#[test]
fn test_memory_pool_allocate_zero_fails() {
    let pool = MemoryPool::new();
    let result = pool.allocate(0);
    assert!(result.is_err());
}

#[test]
fn test_memory_pool_allocate_too_large_fails() {
    let pool = MemoryPool::new();
    let result = pool.allocate(2 * 1024 * 1024); // 2MB > 1MB limit
    assert!(result.is_err());
}

#[test]
fn test_memory_pool_deallocate_pool_limit_succeeds() {
    let pool = MemoryPool::new();

    // Deallocate more than MAX_POOL_SIZE (100) items
    for _ in 0..110 {
        let mem = pool.allocate(16).unwrap();
        pool.deallocate(mem);
    }

    // Should still work (excess items are dropped/zeroized)
    let mem = pool.allocate(16).unwrap();
    assert_eq!(mem.len(), 16);
}

#[test]
fn test_get_memory_pool_singleton_succeeds() {
    let pool1 = get_memory_pool();
    let pool2 = get_memory_pool();
    // Both should point to the same pool (singleton)
    let _mem = pool1.allocate(32).unwrap();
    let _mem2 = pool2.allocate(32).unwrap();
}

// ============================================================================
// RngHandle tests
// ============================================================================

#[test]
fn test_rng_handle_secure_succeeds() {
    let rng = RngHandle::secure().unwrap();
    let mut buf = vec![0u8; 32];
    rng.fill_bytes(&mut buf).unwrap();
    // Should have random data (extremely unlikely to be all zeros)
    assert!(!buf.iter().all(|&b| b == 0));
}

#[test]
fn test_rng_handle_next_u64_succeeds() {
    let rng = RngHandle::secure().unwrap();
    let val = rng.next_u64().unwrap();
    // Just verify it doesn't error (value is random)
    let _ = val;
}

#[test]
fn test_rng_handle_next_u32_succeeds() {
    let rng = RngHandle::secure().unwrap();
    let val = rng.next_u32().unwrap();
    let _ = val;
}

// `RngHandle::ThreadLocal` is backed by ChaCha20Rng, which is NOT FIPS-
// approved. Under `feature = "fips"` the implementation rejects this path
// with `RandomError`, so the success-path test is gated to non-FIPS builds.
// Under FIPS we instead assert the rejection.

#[cfg(not(feature = "fips"))]
#[test]
fn test_rng_handle_thread_local_succeeds() {
    let rng = RngHandle::ThreadLocal;
    let mut buf = vec![0u8; 16];
    rng.fill_bytes(&mut buf).unwrap();
    assert!(!buf.iter().all(|&b| b == 0));

    let val = rng.next_u64().unwrap();
    let _ = val;

    let val = rng.next_u32().unwrap();
    let _ = val;
}

#[cfg(feature = "fips")]
#[test]
fn test_rng_handle_thread_local_rejected_under_fips() {
    let rng = RngHandle::ThreadLocal;
    let mut buf = vec![0u8; 16];
    assert!(matches!(
        rng.fill_bytes(&mut buf),
        Err(latticearc::prelude::error::LatticeArcError::RandomError)
    ));
    assert!(matches!(
        rng.next_u64(),
        Err(latticearc::prelude::error::LatticeArcError::RandomError)
    ));
    assert!(matches!(
        rng.next_u32(),
        Err(latticearc::prelude::error::LatticeArcError::RandomError)
    ));
}

// ============================================================================
// Convenience RNG functions
// ============================================================================

#[test]
fn test_generate_secure_random_bytes_succeeds() {
    let bytes = generate_secure_random_bytes(32).unwrap();
    assert_eq!(bytes.len(), 32);
    assert!(!bytes.iter().all(|&b| b == 0));
}

#[test]
fn test_generate_secure_random_bytes_zero_length_has_correct_size() {
    let bytes = generate_secure_random_bytes(0).unwrap();
    assert!(bytes.is_empty());
}

#[test]
fn test_generate_secure_random_u64_succeeds() {
    let val = generate_secure_random_u64().unwrap();
    let _ = val;
}

#[test]
fn test_generate_secure_random_u32_succeeds() {
    let val = generate_secure_random_u32().unwrap();
    let _ = val;
}

#[test]
fn test_get_global_secure_rng_succeeds() {
    let rng = get_global_secure_rng().unwrap();
    let _ = rng; // Just verify it doesn't error
}

#[test]
fn test_initialize_global_secure_rng_succeeds() {
    let result = initialize_global_secure_rng();
    assert!(result.is_ok());
}
