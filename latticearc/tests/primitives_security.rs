#![deny(unsafe_code)]
#![allow(clippy::unwrap_used)]

//! Coverage tests for security.rs
//!
//! Targets `allocate_secure_buffer`, `RngHandle`, and convenience RNG
//! functions. Round-26 audit fix (M26) removed the `MemoryPool` type
//! (the no-op pool was pure mutex-contention overhead) — the
//! corresponding tests now exercise `allocate_secure_buffer`, the
//! direct replacement.

use latticearc::primitives::security::{
    RngHandle, allocate_secure_buffer, generate_secure_random_bytes, generate_secure_random_u32,
    generate_secure_random_u64, get_global_secure_rng, initialize_global_secure_rng,
    secure_compare, secure_zeroize,
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
// allocate_secure_buffer tests (round-26 audit fix M26: replaces MemoryPool)
// ============================================================================

#[test]
fn test_allocate_secure_buffer_basic_succeeds() {
    let mem = allocate_secure_buffer(64).unwrap();
    assert_eq!(mem.len(), 64);
    assert!(mem.expose_secret().iter().all(|&b| b == 0));
}

#[test]
fn test_allocate_secure_buffer_various_sizes_succeed() {
    for size in [1, 16, 32, 64, 128, 1024] {
        let mem = allocate_secure_buffer(size).unwrap();
        assert_eq!(mem.len(), size);
    }
}

#[test]
fn test_allocate_secure_buffer_zero_fails() {
    let result = allocate_secure_buffer(0);
    assert!(result.is_err());
}

#[test]
fn test_allocate_secure_buffer_too_large_fails() {
    let result = allocate_secure_buffer(2 * 1024 * 1024); // 2MB > 1MB limit
    assert!(result.is_err());
}

#[test]
fn test_allocate_secure_buffer_at_boundary_succeeds() {
    let mem = allocate_secure_buffer(1024 * 1024).unwrap();
    assert_eq!(mem.len(), 1024 * 1024);

    let result = allocate_secure_buffer(1024 * 1024 + 1);
    assert!(result.is_err());
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

// `RngHandle::ThreadLocal` is `#[cfg(not(feature = "fips"))]`-gated at
// the type level, so under `feature = "fips"` the variant does not
// exist and this test is simply absent from the build. The runtime-
// rejection test that previously ran under fips was retired when the
// type-level guard landed (the compiler now refuses constructions that
// the runtime would have rejected).

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
