#![deny(unsafe_code)]
#![warn(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

//! Cryptographically Secure Random Number Generator
//!
//! This module provides CSPRNG using OsRng.

use rand::{RngCore, rngs::OsRng};

/// Generate random bytes
#[must_use]
pub fn random_bytes(count: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; count];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

/// Generate random u32
#[must_use]
pub fn random_u32() -> u32 {
    OsRng.next_u32()
}

/// Generate random u64
#[must_use]
pub fn random_u64() -> u64 {
    OsRng.next_u64()
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
    fn test_random_bytes() {
        let bytes = random_bytes(32);
        assert_eq!(bytes.len(), 32);
    }

    #[test]
    fn test_random_u32() {
        let val = random_u32();
        assert!(val < u32::MAX);
    }

    #[test]
    fn test_random_u64() {
        let val = random_u64();
        assert!(val < u64::MAX);
    }

    // Non-repetition tests
    #[test]
    fn test_random_bytes_no_repetition() {
        let mut seen = HashSet::new();
        for _ in 0..100 {
            let bytes = random_bytes(16);
            assert!(seen.insert(bytes.clone()), "Generated duplicate random bytes");
        }
    }

    #[test]
    fn test_random_u32_no_repetition() {
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
    fn test_random_u64_no_repetition() {
        let mut seen = HashSet::new();
        for _ in 0..1000 {
            let val = random_u64();
            assert!(seen.insert(val), "Generated duplicate u64");
        }
    }

    // Zero-byte tests (ensure output is not trivial)
    #[test]
    fn test_random_bytes_not_all_zeros() {
        let bytes = random_bytes(32);
        assert!(!bytes.iter().all(|&b| b == 0), "Random bytes should not be all zeros");
    }

    #[test]
    fn test_random_bytes_not_all_same() {
        let bytes = random_bytes(32);
        let first = bytes[0];
        assert!(
            !bytes.iter().all(|&b| b == first),
            "Random bytes should not be all the same value"
        );
    }

    // Distribution tests
    #[test]
    fn test_random_bytes_distribution() {
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
    fn test_random_u32_distribution() {
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
    fn test_random_u64_distribution() {
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
    fn test_random_bytes_zero_length() {
        let bytes = random_bytes(0);
        assert_eq!(bytes.len(), 0);
    }

    #[test]
    fn test_random_bytes_large_count() {
        let bytes = random_bytes(1_000_000); // 1MB
        assert_eq!(bytes.len(), 1_000_000);
        // Verify it's not all zeros
        assert!(!bytes.iter().all(|&b| b == 0));
    }

    // Thread safety test (OsRng is thread-safe)
    #[test]
    fn test_random_bytes_concurrent() {
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
    fn test_random_bytes_monobit() {
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

        // For a good CSPRNG, ratio should be close to 0.5
        // Allow reasonable deviation: 0.48 to 0.52
        assert!(
            ones_ratio > 0.48 && ones_ratio < 0.52,
            "Monobit test failed: ones ratio = {}",
            ones_ratio
        );
    }
}
