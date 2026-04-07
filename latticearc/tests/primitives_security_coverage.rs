#![deny(unsafe_code)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::panic)]
#![allow(clippy::indexing_slicing)]
#![allow(clippy::cast_possible_truncation)]
#![allow(missing_docs)]

//! Coverage tests for security.rs
//!
//! Targets uncovered paths in SecureBytes, MemoryPool, RngHandle,
//! and convenience RNG functions.

use latticearc::primitives::security::{
    MemoryPool, RngHandle, SecureBytes, generate_secure_random_bytes, generate_secure_random_u32,
    generate_secure_random_u64, get_global_secure_rng, get_memory_pool,
    initialize_global_secure_rng, secure_compare, secure_zeroize,
};

// ============================================================================
// SecureBytes tests
// ============================================================================

#[test]
fn test_secure_bytes_new_and_accessors_succeeds() {
    let data = vec![1u8, 2, 3, 4, 5];
    let sb = SecureBytes::new(data.clone());
    assert_eq!(sb.len(), 5);
    assert!(!sb.is_empty());
    assert_eq!(sb.as_slice(), &data[..]);
    assert!(sb.capacity() >= 5);
}

#[test]
fn test_secure_bytes_from_slice_succeeds() {
    let data = [10u8, 20, 30];
    let sb = SecureBytes::from(&data);
    assert_eq!(sb.len(), 3);
    assert_eq!(sb.as_slice(), &data);
}

#[test]
fn test_secure_bytes_zeros_succeeds() {
    let sb = SecureBytes::zeros(16);
    assert_eq!(sb.len(), 16);
    assert!(sb.as_slice().iter().all(|&b| b == 0));
}

#[test]
fn test_secure_bytes_empty_succeeds() {
    let sb = SecureBytes::new(vec![]);
    assert!(sb.is_empty());
    assert_eq!(sb.len(), 0);
}

#[test]
fn test_secure_bytes_extend_succeeds() {
    let mut sb = SecureBytes::new(vec![1, 2]);
    sb.extend_from_slice(&[3, 4, 5]);
    assert_eq!(sb.len(), 5);
    assert_eq!(sb.as_slice(), &[1, 2, 3, 4, 5]);
}

#[test]
fn test_secure_bytes_as_mut_slice_succeeds() {
    let mut sb = SecureBytes::new(vec![0u8; 4]);
    let slice = sb.as_mut_slice();
    slice[0] = 0xFF;
    assert_eq!(sb.as_slice()[0], 0xFF);
}

#[test]
fn test_secure_bytes_into_vec_succeeds() {
    let sb = SecureBytes::new(vec![10, 20, 30]);
    let v = sb.into_vec();
    assert_eq!(v, vec![10, 20, 30]);
}

#[test]
fn test_secure_bytes_resize_succeeds() {
    let mut sb = SecureBytes::new(vec![1, 2, 3]);
    sb.resize(5);
    assert_eq!(sb.len(), 5);
    assert_eq!(&sb.as_slice()[..3], &[1, 2, 3]);
    assert_eq!(&sb.as_slice()[3..], &[0, 0]); // New bytes zeroed

    sb.resize(2);
    assert_eq!(sb.len(), 2);
}

#[test]
fn test_secure_bytes_deref_succeeds() {
    let sb = SecureBytes::new(vec![1, 2, 3]);
    let slice: &[u8] = &sb;
    assert_eq!(slice, &[1, 2, 3]);
}

#[test]
fn test_secure_bytes_deref_mut_succeeds() {
    let mut sb = SecureBytes::new(vec![0u8; 3]);
    let slice: &mut [u8] = &mut sb;
    slice[1] = 42;
    assert_eq!(sb.as_slice()[1], 42);
}

#[test]
fn test_secure_bytes_as_ref_succeeds() {
    let sb = SecureBytes::new(vec![5, 6, 7]);
    let r: &[u8] = sb.as_ref();
    assert_eq!(r, &[5, 6, 7]);
}

#[test]
fn test_secure_bytes_debug_redacted_succeeds() {
    let sb = SecureBytes::new(vec![0xDE, 0xAD]);
    let debug = format!("{:?}", sb);
    assert!(debug.contains("REDACTED"));
    assert!(debug.contains("2 bytes"));
    // Should NOT contain actual data
    assert!(!debug.contains("DE"));
}

#[test]
fn test_secure_bytes_constant_time_eq_succeeds() {
    let a = SecureBytes::new(vec![1, 2, 3]);
    let b = SecureBytes::new(vec![1, 2, 3]);
    let c = SecureBytes::new(vec![1, 2, 4]);
    let d = SecureBytes::new(vec![1, 2]);

    assert_eq!(a, b);
    assert_ne!(a, c);
    assert_ne!(a, d); // Different lengths
}

// Clone intentionally removed from SecureBytes to prevent copies of secret data

#[test]
fn test_secure_bytes_from_vec_succeeds() {
    let v = vec![1u8, 2, 3];
    let sb: SecureBytes = v.into();
    assert_eq!(sb.len(), 3);
}

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
    assert!(mem.as_slice().iter().all(|&b| b == 0));
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
