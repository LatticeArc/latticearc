//! Constant-Time Verification Tests
//!
//! These tests use ctgrind (Valgrind memcheck) to verify that cryptographic
//! operations do not leak secrets through control flow or memory access patterns.
//!
//! ## How ctgrind Works
//!
//! 1. Mark secret data as "uninitialized" using Valgrind annotations
//! 2. Valgrind tracks this data through the program
//! 3. If the data influences a branch or memory address, Valgrind reports an error
//!
//! ## Running These Tests
//!
//! ```bash
//! # Install Valgrind (if not already installed)
//! # Ubuntu/Debian: sudo apt-get install valgrind
//! # macOS: brew install valgrind
//!
//! # Run constant-time tests under Valgrind
//! cargo test --test constant_time --release
//! valgrind --tool=memcheck target/release/deps/constant_time-*
//! ```
//!
//! ## CI Integration
//!
//! These tests are run in CI on Linux (Valgrind not available on macOS/Windows).
//!
//! ## Limitations
//!
//! ctgrind catches:
//! - ✅ Control flow leaks (if statements on secrets)
//! - ✅ Memory access leaks (array[secret])
//!
//! ctgrind does NOT catch:
//! - ❌ Cache-timing attacks
//! - ❌ Speculative execution side-channels
//!
//! For primitives (AES-GCM, ML-KEM, etc.), we rely on aws-lc-rs's formal
//! verification: https://github.com/awslabs/aws-lc-verification

#![cfg(all(test, target_os = "linux"))] // ctgrind requires Valgrind (Linux-only)
#![allow(unused_imports)] // ctgrind macros are conditionally compiled

use arc_primitives::aead::{AesGcm256, AesGcmOperations};
use ctgrind::poison;
use subtle::ConstantTimeEq;

/// Verify that key comparison is constant-time
///
/// This test ensures that comparing two keys does not leak information
/// through branching or memory access patterns.
#[test]
fn test_key_comparison_constant_time() {
    let key1 = vec![0x42u8; 32];
    let key2 = vec![0x43u8; 32];

    // Mark keys as secret (poisoned in Valgrind terminology)
    unsafe {
        poison(key1.as_ptr(), key1.len());
        poison(key2.as_ptr(), key2.len());
    }

    // This operation must be constant-time
    // If ct_eq() branches on the key bytes, Valgrind will report an error
    let result = key1.ct_eq(&key2);

    // Force use of result to prevent optimization
    assert!(!bool::from(result));
}

/// Verify that nonce comparison is constant-time
#[test]
fn test_nonce_comparison_constant_time() {
    let nonce1 = vec![0xAAu8; 12];
    let nonce2 = vec![0xBBu8; 12];

    unsafe {
        poison(nonce1.as_ptr(), nonce1.len());
        poison(nonce2.as_ptr(), nonce2.len());
    }

    let result = nonce1.ct_eq(&nonce2);
    assert!(!bool::from(result));
}

/// Verify that MAC tag comparison is constant-time
///
/// This is critical for preventing timing attacks on authentication.
#[test]
fn test_tag_comparison_constant_time() {
    let tag1 = vec![0x11u8; 16];
    let tag2 = vec![0x22u8; 16];

    unsafe {
        poison(tag1.as_ptr(), tag1.len());
        poison(tag2.as_ptr(), tag2.len());
    }

    let result = tag1.ct_eq(&tag2);
    assert!(!bool::from(result));
}

/// Verify that conditional selection is constant-time
///
/// This tests the `subtle::Choice` type's constant-time selection.
#[test]
fn test_conditional_select_constant_time() {
    use subtle::{Choice, ConditionallySelectable};

    let a = 0x42u8;
    let b = 0x43u8;
    let condition = 1u8; // Secret condition

    unsafe {
        poison(&condition as *const u8, 1);
    }

    let choice = Choice::from(condition);
    let result = u8::conditional_select(&a, &b, choice);

    // Force use to prevent optimization
    assert!(result == 0x42 || result == 0x43);
}

// Note: We do NOT test AES-GCM encryption/decryption here because:
// 1. Those primitives come from aws-lc-rs, which is formally verified
// 2. Testing them would be redundant and add CI overhead
// 3. We only test our own API layer (comparisons, selections)
//
// See: https://github.com/awslabs/aws-lc-verification
