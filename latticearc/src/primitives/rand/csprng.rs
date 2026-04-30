#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

//! Cryptographically Secure Random Number Generator
//!
//! This module provides CSPRNG using OsRng.
//!
//! # Failure semantics — process abort vs `Result`
//!
//! There are TWO public entry points to OS entropy in this crate, and they
//! handle OS-RNG failure differently. Callers must understand the split:
//!
//! - **`csprng::random_bytes` / `random_u32` / `random_u64`** (this module):
//!   collapse `TryRngCore` errors via `expect("OS RNG failure")` and
//!   **panic, aborting the process** if the OS RNG returns an error. Use
//!   when an OS RNG failure should be treated as fatal.
//! - **`security::RngHandle::fill_bytes`** (sibling module): returns
//!   `Result<()>`. Use when the calling code must surface entropy failure
//!   gracefully (e.g. FIPS deployments, restricted-entropy CI sandboxes).
//!
//! This split is intentional. An OS RNG failure on a modern system
//! (Linux `getrandom`, macOS `getentropy`, Windows `BCryptGenRandom`)
//! means the entropy source is broken; continuing without secure
//! randomness would be more dangerous than aborting. But for
//! environments where graceful degradation matters more than
//! fail-fast, the `RngHandle` path provides the alternative.
//!
//! # `rand` 0.9 migration note
//!
//! `rand` 0.9 made the OS RNG fallible at the type level — `rand_core::OsRng`
//! now implements `TryRngCore` (returning `Result`) rather than `RngCore`
//! (infallible). This file is the single, audited place where that fallibility
//! is collapsed back to a panic. The `expect`/`unwrap` escape lives here only
//! and is explicitly documented; everywhere else uses these wrappers or
//! [`secure_rng()`] to stay clippy-clean.

use rand::{CryptoRng, TryRngCore, rngs::OsRng};

/// Returns an infallible CSPRNG suitable as a `RngCore + CryptoRng` argument.
///
/// Internally, this wraps `rand::rngs::OsRng` (which is `TryRngCore` in
/// `rand` 0.9) in `rand_core::UnwrapErr`, panicking on OS-RNG failure. See
/// the module-level docs for why panicking is the right semantic for
/// `getrandom`/`/dev/urandom` failure on modern systems.
///
/// # Panics
///
/// Panics if the OS entropy source returns an error during a subsequent
/// `fill_bytes` / `next_u32` / `next_u64` call on the returned RNG. See
/// module-level docs.
// `pub` rather than `pub(crate)` because integration tests in
// `latticearc/tests/*.rs` (which live outside the crate root) need a
// `CryptoRng`-shaped RNG for property/proptest fixtures. External
// callers should prefer [`random_bytes`] / [`random_u32`] / [`random_u64`].
#[doc(hidden)]
#[must_use]
pub fn secure_rng() -> impl CryptoRng {
    rand_core::UnwrapErr(OsRng)
}

/// Generate random bytes.
///
/// # Panics
///
/// Panics if the OS entropy source returns an error. See module-level docs
/// for why this is the right semantic for `getrandom` failure on modern systems.
#[must_use]
pub fn random_bytes(count: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; count];
    #[allow(clippy::expect_used)] // see module-level rand 0.9 migration note
    OsRng.try_fill_bytes(&mut bytes).expect("OS RNG failure");
    bytes
}

/// Generate random u32.
///
/// # Panics
///
/// Panics if the OS entropy source returns an error. See module-level docs.
#[must_use]
pub fn random_u32() -> u32 {
    #[allow(clippy::expect_used)] // see module-level rand 0.9 migration note
    OsRng.try_next_u32().expect("OS RNG failure")
}

/// Generate random u64.
///
/// # Panics
///
/// Panics if the OS entropy source returns an error. See module-level docs.
#[must_use]
pub fn random_u64() -> u64 {
    #[allow(clippy::expect_used)] // see module-level rand 0.9 migration note
    OsRng.try_next_u64().expect("OS RNG failure")
}

#[cfg(test)]
#[allow(clippy::panic_in_result_fn)] // Tests use assertions for verification
#[allow(clippy::indexing_slicing)] // Tests use direct indexing
#[allow(clippy::cast_possible_truncation)] // Tests cast sizes for testing
#[allow(clippy::cast_lossless)] // Tests use simple casts
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn test_random_bytes_has_correct_length_has_correct_size() {
        let bytes = random_bytes(32);
        assert_eq!(bytes.len(), 32);
    }

    #[test]
    fn test_random_u32_is_within_range_succeeds() {
        let val = random_u32();
        assert!(val < u32::MAX);
    }

    #[test]
    fn test_random_u64_is_within_range_succeeds() {
        let val = random_u64();
        assert!(val < u64::MAX);
    }

    // Non-repetition tests
    #[test]
    fn test_random_bytes_no_repetition_are_unique() {
        let mut seen = HashSet::new();
        for _ in 0..100 {
            let bytes = random_bytes(16);
            assert!(seen.insert(bytes.clone()), "Generated duplicate random bytes");
        }
    }

    #[test]
    fn test_random_u32_no_repetition_are_mostly_unique() {
        let mut seen = HashSet::new();
        for _ in 0..1000 {
            let val = random_u32();
            seen.insert(val);
        }
        // With 1000 samples from 2^32 space, duplicates are extremely unlikely
        // If we get less than 990 unique values, something is wrong
        assert!(seen.len() > 990, "Too many duplicate u32 values");
    }

    #[test]
    fn test_random_u64_no_repetition_are_unique() {
        let mut seen = HashSet::new();
        for _ in 0..1000 {
            let val = random_u64();
            assert!(seen.insert(val), "Generated duplicate u64");
        }
    }

    // Zero-byte tests (ensure output is not trivial)
    #[test]
    fn test_random_bytes_not_all_zeros_is_correct() {
        let bytes = random_bytes(32);
        assert!(!bytes.iter().all(|&b| b == 0), "Random bytes should not be all zeros");
    }

    #[test]
    fn test_random_bytes_not_all_same_is_correct() {
        let bytes = random_bytes(32);
        let first = bytes[0];
        assert!(
            !bytes.iter().all(|&b| b == first),
            "Random bytes should not be all the same value"
        );
    }

    // Distribution tests
    #[test]
    fn test_random_bytes_distribution_is_correct() {
        // Generate a large sample and check basic distribution
        let sample_size = 10_000;
        let bytes = random_bytes(sample_size);

        // Count frequency of each byte value (0-255)
        let mut counts = [0u32; 256];
        for &byte in &bytes {
            counts[byte as usize] += 1;
        }

        // Expected frequency: sample_size / 256 = ~39
        let expected = (sample_size / 256) as u32;

        // Check that no byte value is extremely over or under-represented
        // Allow 5x deviation (very loose bound for CSPRNG)
        for count in counts {
            assert!(
                count < expected * 5,
                "Byte value appears too frequently: {} (expected ~{})",
                count,
                expected
            );
        }

        // Check that most byte values appear at least once in 10k samples
        let unique_values = counts.iter().filter(|&&c| c > 0).count();
        assert!(unique_values > 200, "Too few unique byte values: {}", unique_values);
    }

    #[test]
    fn test_random_u32_distribution_is_correct() {
        // Generate samples and check they span the range
        let sample_size = 1000;
        let mut samples = Vec::with_capacity(sample_size);
        for _ in 0..sample_size {
            samples.push(random_u32());
        }

        // Check we have values in different ranges
        let quarter = u32::MAX / 4;
        let three_quarters = u32::MAX / 4 * 3;
        let has_low = samples.iter().any(|&v| v < quarter);
        let has_mid = samples.iter().any(|&v| v >= quarter && v < three_quarters);
        let has_high = samples.iter().any(|&v| v >= three_quarters);

        assert!(has_low && has_mid && has_high, "u32 values should span the range");
    }

    #[test]
    fn test_random_u64_distribution_is_correct() {
        // Generate samples and check they span the range
        let sample_size = 1000;
        let mut samples = Vec::with_capacity(sample_size);
        for _ in 0..sample_size {
            samples.push(random_u64());
        }

        // Check we have values in different ranges
        let quarter = u64::MAX / 4;
        let three_quarters = u64::MAX / 4 * 3;
        let has_low = samples.iter().any(|&v| v < quarter);
        let has_mid = samples.iter().any(|&v| v >= quarter && v < three_quarters);
        let has_high = samples.iter().any(|&v| v >= three_quarters);

        assert!(has_low && has_mid && has_high, "u64 values should span the range");
    }

    // Edge case tests
    #[test]
    fn test_random_bytes_zero_length_is_correct() {
        let bytes = random_bytes(0);
        assert_eq!(bytes.len(), 0);
    }

    #[test]
    fn test_random_bytes_large_count_has_correct_length_has_correct_size() {
        let bytes = random_bytes(1_000_000); // 1MB
        assert_eq!(bytes.len(), 1_000_000);
        // Verify it's not all zeros
        assert!(!bytes.iter().all(|&b| b == 0));
    }

    // Thread safety test (OsRng is thread-safe)
    #[test]
    fn test_random_bytes_concurrent_are_unique() {
        use std::sync::Arc;
        use std::sync::Mutex;
        use std::thread;

        let results = Arc::new(Mutex::new(Vec::new()));
        let mut handles = vec![];

        for _ in 0..10 {
            let results_clone = Arc::clone(&results);
            let handle = thread::spawn(move || {
                let bytes = random_bytes(16);
                results_clone.lock().map(|mut r| r.push(bytes)).ok();
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().ok();
        }

        let results = results.lock().map(|r| r.clone()).unwrap_or_default();
        assert_eq!(results.len(), 10);

        // Check all results are unique
        let mut seen = HashSet::new();
        for result in results {
            assert!(seen.insert(result), "Concurrent calls generated duplicate values");
        }
    }

    // Monobit test (NIST SP 800-22 simplified version)
    #[test]
    fn test_random_bytes_monobit_is_within_threshold_succeeds() {
        let bytes = random_bytes(1000);
        let mut ones = 0;
        let mut zeros = 0;

        for byte in bytes {
            for bit in 0..8 {
                if (byte >> bit) & 1 == 1 {
                    ones += 1;
                } else {
                    zeros += 1;
                }
            }
        }

        let total = ones + zeros;
        let ones_ratio = ones as f64 / total as f64;

        // For a good CSPRNG the 1-bit proportion converges to 0.5.
        // For 8000 bits, σ = sqrt(0.25/8000) ≈ 0.0056. The accepted
        // band of ±0.04 ≈ 7σ keeps false-positive rate below 1 in
        // 10^11 while still flagging catastrophic CSPRNG bias (a real
        // ≥4% bias is a 7σ event in this sample size).
        assert!(
            ones_ratio > 0.46 && ones_ratio < 0.54,
            "Monobit test failed: ones ratio = {}",
            ones_ratio
        );
    }
}
