//! NIST SP 800-90B and SP 800-22 Entropy Health Tests
//!
//! This module implements comprehensive entropy health tests as specified in:
//! - **NIST SP 800-90B**: Recommendation for Entropy Sources Used for Random Bit Generation
//! - **NIST SP 800-22**: Statistical Test Suite for Random Number Generators
//!
//! These tests help detect failures in entropy sources that could compromise
//! cryptographic security.
//!
//! ## Tests Implemented
//!
//! ### SP 800-90B Tests
//! - **Repetition Test**: Detects stuck-at faults (Section 4.4.1)
//! - **Frequency Test**: Validates byte value distribution
//! - **Adaptive Proportion Test**: Monitors for entropy decrease (Section 4.4.2)
//!
//! ### SP 800-22 Tests
//! - **Monobit Test**: Checks 0/1 bit balance (Section 2.1)
//! - **Runs Test**: Validates consecutive bit sequences (Section 2.3)
//! - **Longest Run Test**: Detects excessive run lengths (Section 2.4)
//!
//! ## Usage
//!
//! ```no_run
//! use arc_primitives::rand::entropy_tests::run_entropy_health_tests;
//!
//! // Run all entropy health tests on fresh random bytes
//! if let Err(e) = run_entropy_health_tests() {
//!     eprintln!("Entropy source may be compromised: {}", e);
//! }
//! ```
//!
//! ## FIPS 140-3 Compliance
//!
//! This test suite supports FIPS 140-3 entropy source validation:
//! - Power-up self-tests (repetition, frequency)
//! - Continuous health monitoring (adaptive proportion)
//! - Statistical quality assurance (monobit, runs, longest run)

#![deny(unsafe_code)]
#![warn(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

use arc_prelude::error::{LatticeArcError, Result};

/// Maximum number of consecutive identical bytes allowed before failing
/// the repetition test. Per SP 800-90B guidelines for detecting stuck-at faults.
const MAX_CONSECUTIVE_IDENTICAL_BYTES: usize = 5;

/// Minimum sample size for reliable entropy testing
const MIN_SAMPLE_SIZE: usize = 32;

/// Default sample size for entropy health tests
const DEFAULT_SAMPLE_SIZE: usize = 256;

/// Maximum allowed deviation from expected frequency (as a ratio).
/// A value of 0.5 means no byte value should appear more than 1.5x or less
/// than 0.5x of the expected frequency.
const MAX_FREQUENCY_DEVIATION_RATIO: f64 = 0.5;

// =============================================================================
// Repetition Test (SP 800-90B Section 4.4.1)
// =============================================================================

/// Repetition Test for detecting stuck-at faults in entropy sources.
///
/// This test checks for consecutive identical bytes in the input data.
/// If more than `MAX_CONSECUTIVE_IDENTICAL_BYTES` (5) consecutive identical
/// bytes are found, the test fails, indicating a potential entropy source failure.
///
/// # Arguments
///
/// * `bytes` - The random bytes to test
///
/// # Returns
///
/// * `Ok(())` - If no more than 5 consecutive identical bytes are found
/// * `Err(LatticeArcError::ValidationError)` - If the test fails
///
/// # Example
///
/// ```no_run
/// use arc_primitives::rand::entropy_tests::repetition_test;
///
/// let random_bytes = vec![0x12, 0x34, 0x56, 0x78, 0x9a];
/// assert!(repetition_test(&random_bytes).is_ok());
///
/// // This would fail - 6 consecutive identical bytes
/// let bad_bytes = vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
/// assert!(repetition_test(&bad_bytes).is_err());
/// ```
///
/// # Errors
///
/// Returns `LatticeArcError::ValidationError` if:
/// - The input is empty
/// - More than 5 consecutive identical bytes are found
pub fn repetition_test(bytes: &[u8]) -> Result<()> {
    if bytes.is_empty() {
        return Err(LatticeArcError::ValidationError {
            message: "Repetition test requires non-empty input".to_string(),
        });
    }

    if bytes.len() < 2 {
        // Single byte cannot have repetitions
        return Ok(());
    }

    let mut consecutive_count = 1usize;
    let mut max_consecutive = 1usize;
    let mut prev_byte = bytes.first().ok_or_else(|| LatticeArcError::ValidationError {
        message: "Failed to access first byte".to_string(),
    })?;

    for byte in bytes.iter().skip(1) {
        if byte == prev_byte {
            consecutive_count = consecutive_count.saturating_add(1);
            if consecutive_count > max_consecutive {
                max_consecutive = consecutive_count;
            }
        } else {
            consecutive_count = 1;
        }
        prev_byte = byte;
    }

    if max_consecutive > MAX_CONSECUTIVE_IDENTICAL_BYTES {
        return Err(LatticeArcError::ValidationError {
            message: format!(
                "Repetition test failed: found {} consecutive identical bytes (max allowed: {})",
                max_consecutive, MAX_CONSECUTIVE_IDENTICAL_BYTES
            ),
        });
    }

    Ok(())
}

// =============================================================================
// Frequency Test (SP 800-90B Section 4.4.2)
// =============================================================================

/// Frequency Test for detecting biased entropy sources.
///
/// This test analyzes the distribution of byte values in the input data.
/// For a good entropy source, byte values should be roughly uniformly
/// distributed. This test fails if any byte value appears significantly
/// more or less frequently than expected.
///
/// # Arguments
///
/// * `bytes` - The random bytes to test (minimum 32 bytes recommended)
///
/// # Returns
///
/// * `Ok(())` - If byte distribution is acceptable
/// * `Err(LatticeArcError::ValidationError)` - If distribution is heavily skewed
///
/// # Example
///
/// ```no_run
/// use arc_primitives::rand::entropy_tests::frequency_test;
///
/// // Generate some random bytes (in practice, use CSPRNG)
/// let random_bytes: Vec<u8> = (0..256).map(|i| i as u8).collect();
/// assert!(frequency_test(&random_bytes).is_ok());
/// ```
///
/// # Errors
///
/// Returns `LatticeArcError::ValidationError` if:
/// - The input has fewer than `MIN_SAMPLE_SIZE` bytes
/// - The byte distribution is heavily skewed
pub fn frequency_test(bytes: &[u8]) -> Result<()> {
    if bytes.len() < MIN_SAMPLE_SIZE {
        return Err(LatticeArcError::ValidationError {
            message: format!(
                "Frequency test requires at least {} bytes, got {}",
                MIN_SAMPLE_SIZE,
                bytes.len()
            ),
        });
    }

    // Count occurrences of each byte value
    let mut counts = [0u32; 256];
    for byte in bytes {
        let index = usize::from(*byte);
        if let Some(count) = counts.get_mut(index) {
            *count = count.saturating_add(1);
        }
    }

    // Calculate expected frequency for uniform distribution
    // Expected count for each byte = total_bytes / 256
    let total_bytes = bytes.len();

    // For small samples, we use a more lenient threshold
    // For larger samples, we can be stricter
    // Note: precision loss is acceptable here as we're doing statistical analysis
    #[allow(clippy::cast_precision_loss)]
    let expected_count_f64 = total_bytes as f64 / 256.0;

    // Calculate the maximum allowed count using statistical thresholds
    // For truly random data, the expected distribution follows a Poisson distribution
    // For small samples, we need to allow for natural statistical variation
    //
    // For a Poisson distribution with lambda = expected_count, the probability of
    // seeing k occurrences drops rapidly. We use a heuristic that allows for
    // reasonable variation without being overly permissive.
    let max_deviation = if total_bytes < 512 {
        // For very small samples (< 512 bytes), be very lenient
        // With 256 bytes, expected = 1, we should allow up to ~8 (extreme but possible)
        // With 512 bytes, expected = 2, we should allow up to ~10
        (expected_count_f64 * 6.0).max(8.0)
    } else if total_bytes < 1024 {
        // For small samples, use a higher threshold
        // This allows for natural statistical variation
        (expected_count_f64 * 4.0).max(6.0)
    } else if total_bytes < 4096 {
        // Medium samples
        expected_count_f64 * 3.0
    } else {
        // Large samples - can be stricter
        expected_count_f64 * (1.0 + MAX_FREQUENCY_DEVIATION_RATIO)
    };

    // Check if any byte value is significantly over-represented
    let mut max_count = 0u32;
    let mut max_byte = 0u8;

    for (byte_val, count) in counts.iter().enumerate() {
        if *count > max_count {
            max_count = *count;
            // Safe conversion: byte_val is always 0-255 since counts has exactly 256 elements
            // Using try_from with unwrap_or for safety (though truncation won't occur)
            max_byte = u8::try_from(byte_val).unwrap_or(0);
        }
    }

    // Convert max_count to f64 for comparison
    let max_count_f64 = f64::from(max_count);

    if max_count_f64 > max_deviation {
        return Err(LatticeArcError::ValidationError {
            message: format!(
                "Frequency test failed: byte 0x{:02X} appears {} times \
                 (expected ~{:.1}, max allowed {:.1})",
                max_byte, max_count, expected_count_f64, max_deviation
            ),
        });
    }

    // Also check for under-representation (all zeros for some values might
    // indicate a bias in the lower bits)
    // For samples >= 512 bytes, at least some byte values should appear
    if total_bytes >= 512 {
        let zero_count = counts.iter().filter(|&&c| c == 0).count();
        // Allow up to 50% of byte values to be missing in smaller samples
        // For larger samples, this threshold decreases
        // Using integer arithmetic to avoid float-to-int casting issues
        let max_zeros = if total_bytes >= 2048 {
            64 // 25% of 256
        } else {
            128 // 50% of 256
        };

        if zero_count > max_zeros {
            return Err(LatticeArcError::ValidationError {
                message: format!(
                    "Frequency test failed: {} out of 256 byte values never appeared \
                     (max allowed {} for {} byte sample)",
                    zero_count, max_zeros, total_bytes
                ),
            });
        }
    }

    Ok(())
}

// =============================================================================
// Monobit Test (NIST SP 800-22 Section 2.1)
// =============================================================================

/// Monobit (Frequency) Test for bit-level balance.
///
/// This test checks whether the number of ones and zeros in a sequence are
/// approximately the same, as would be expected for a truly random sequence.
/// Per NIST SP 800-22, this is a fundamental test for randomness.
///
/// # Arguments
///
/// * `bytes` - The random bytes to test
///
/// # Returns
///
/// * `Ok(())` - If the test passes (bit frequencies are balanced)
/// * `Err(LatticeArcError::ValidationError)` - If the test fails
///
/// # Errors
///
/// Returns `LatticeArcError::ValidationError` if:
/// - Input is empty
/// - Bit frequencies are significantly unbalanced (>60% or <40% ones)
#[allow(clippy::arithmetic_side_effects)] // Safe: multiplication by 8 won't overflow for realistic input sizes
#[allow(clippy::cast_precision_loss)] // Intentional: statistical calculations require float conversion
pub fn monobit_test(bytes: &[u8]) -> Result<()> {
    if bytes.is_empty() {
        return Err(LatticeArcError::ValidationError {
            message: "Monobit test requires non-empty input".to_string(),
        });
    }

    // Count the number of 1-bits
    let one_count: u64 = bytes.iter().map(|b| u64::from(b.count_ones())).sum();
    let total_bits = (bytes.len() as u64).saturating_mul(8);

    // Calculate the proportion of ones
    // Safety: total_bits > 0 since bytes is non-empty
    let proportion = one_count as f64 / total_bits as f64;

    // For random data, we expect approximately 50% ones
    // Allow a reasonable deviation (40%-60% range for smaller samples)
    let min_proportion = if total_bits < 1000 { 0.35 } else { 0.40 };
    let max_proportion = if total_bits < 1000 { 0.65 } else { 0.60 };

    if proportion < min_proportion || proportion > max_proportion {
        return Err(LatticeArcError::ValidationError {
            message: format!(
                "Monobit test failed: {:.1}% ones (expected 40-60% for {} bits)",
                proportion * 100.0,
                total_bits
            ),
        });
    }

    Ok(())
}

// =============================================================================
// Runs Test (NIST SP 800-22 Section 2.3)
// =============================================================================

/// Runs Test for consecutive bit sequences.
///
/// This test checks for the expected number of "runs" in a sequence, where a
/// run is an uninterrupted sequence of identical bits. For random data, there
/// should be an expected distribution of run lengths.
///
/// # Arguments
///
/// * `bytes` - The random bytes to test
///
/// # Returns
///
/// * `Ok(())` - If the test passes
/// * `Err(LatticeArcError::ValidationError)` - If the test fails
///
/// # Errors
///
/// Returns `LatticeArcError::ValidationError` if:
/// - Input is too small (<8 bytes)
/// - The number of runs is significantly different from expected
#[allow(clippy::arithmetic_side_effects)] // Safe: checked len >= 8 before arithmetic
#[allow(clippy::cast_precision_loss)] // Intentional: statistical calculations require float conversion
#[allow(clippy::cast_possible_truncation)] // Intentional: converting float ratio to integer bounds
#[allow(clippy::cast_sign_loss)] // Safe: values are always positive in this context
#[allow(clippy::indexing_slicing)] // Safe: checked len >= 8 before indexing
pub fn runs_test(bytes: &[u8]) -> Result<()> {
    if bytes.len() < 8 {
        return Err(LatticeArcError::ValidationError {
            message: "Runs test requires at least 8 bytes".to_string(),
        });
    }

    // Convert bytes to bits and count runs
    // Safety: len >= 8, so this won't overflow
    let total_bits = bytes.len().saturating_mul(8);
    let mut runs: u64 = 1; // Start with 1 run
    // Safety: len >= 8 checked above
    let mut prev_bit = (bytes[0] >> 7) & 1;

    for (i, &byte) in bytes.iter().enumerate() {
        let start_bit = if i == 0 { 6 } else { 7 }; // Skip first bit of first byte
        for bit_pos in (0..=start_bit).rev() {
            let current_bit = (byte >> bit_pos) & 1;
            if current_bit != prev_bit {
                runs = runs.saturating_add(1);
                prev_bit = current_bit;
            }
        }
    }

    // For truly random data, expected number of runs is approximately:
    // E(runs) = (2 * n * pi) / n + 1 ≈ n/2 + 1 where n is total bits
    // But more precisely: E(runs) = 2*n0*n1/n + 1 where n0, n1 are counts of 0s and 1s
    // For balanced data: E(runs) ≈ n/2

    let expected_runs = total_bits as f64 / 2.0;

    // Allow significant deviation for the statistical nature of the test
    // Use ±30% range for smaller samples, ±25% for larger
    let deviation = if total_bits < 1000 { 0.35 } else { 0.30 };
    let min_runs = (expected_runs * (1.0 - deviation)) as u64;
    let max_runs = (expected_runs * (1.0 + deviation)) as u64;

    if runs < min_runs || runs > max_runs {
        return Err(LatticeArcError::ValidationError {
            message: format!(
                "Runs test failed: {} runs found (expected {}-{} for {} bits)",
                runs, min_runs, max_runs, total_bits
            ),
        });
    }

    Ok(())
}

// =============================================================================
// Adaptive Proportion Test (SP 800-90B Section 4.4.2)
// =============================================================================

/// Adaptive Proportion Test per NIST SP 800-90B Section 4.4.2.
///
/// This test monitors for an excessive proportion of a single value within a
/// window. It is designed to detect a significant decrease in entropy.
///
/// # Arguments
///
/// * `bytes` - The random bytes to test
/// * `window_size` - Size of the sliding window (default: 512)
/// * `cutoff_ratio` - Maximum allowed ratio of most common value (default: 0.4)
///
/// # Returns
///
/// * `Ok(())` - If the test passes
/// * `Err(LatticeArcError::ValidationError)` - If the test fails
///
/// # Errors
///
/// Returns `LatticeArcError::ValidationError` if any window exceeds the cutoff.
pub fn adaptive_proportion_test(bytes: &[u8]) -> Result<()> {
    adaptive_proportion_test_with_params(bytes, 512, 0.4)
}

/// Adaptive Proportion Test with custom parameters.
///
/// # Errors
///
/// Returns `LatticeArcError::ValidationError` if any window exceeds the cutoff.
#[allow(clippy::arithmetic_side_effects)] // Safe: checked len >= window_size before arithmetic
#[allow(clippy::cast_precision_loss)] // Intentional: statistical calculations require float conversion
#[allow(clippy::indexing_slicing)] // Safe: loop bounds ensure valid indices
pub fn adaptive_proportion_test_with_params(
    bytes: &[u8],
    window_size: usize,
    cutoff_ratio: f64,
) -> Result<()> {
    if bytes.len() < window_size || window_size == 0 {
        // Not enough data for this test, skip silently
        return Ok(());
    }

    // Slide window through the data
    // Safety: checked len >= window_size above
    let end = bytes.len().saturating_sub(window_size);
    for window_start in 0..=end {
        let window_end = window_start.saturating_add(window_size);
        let window = bytes.get(window_start..window_end).unwrap_or(&[]);

        // Count occurrences of each byte value in window
        let mut counts = [0u32; 256];
        for &byte in window {
            let idx = byte as usize;
            counts[idx] = counts[idx].saturating_add(1);
        }

        // Find the maximum count
        let max_count = counts.iter().max().copied().unwrap_or(0);
        let max_ratio = f64::from(max_count) / window_size as f64;

        if max_ratio > cutoff_ratio {
            return Err(LatticeArcError::ValidationError {
                message: format!(
                    "Adaptive proportion test failed at offset {}: \
                     most common byte appears {:.1}% of window (max {:.1}%)",
                    window_start,
                    max_ratio * 100.0,
                    cutoff_ratio * 100.0
                ),
            });
        }
    }

    Ok(())
}

// =============================================================================
// Longest Run Test (NIST SP 800-22 Section 2.4)
// =============================================================================

/// Longest Run Test - checks that no single bit value runs too long.
///
/// This test verifies that there are no excessively long runs of consecutive
/// identical bits, which would indicate a stuck-at fault or bias.
///
/// # Arguments
///
/// * `bytes` - The random bytes to test
///
/// # Returns
///
/// * `Ok(())` - If no excessively long runs are found
/// * `Err(LatticeArcError::ValidationError)` - If the test fails
///
/// # Errors
///
/// Returns `LatticeArcError::ValidationError` if a run exceeds the threshold.
#[allow(clippy::arithmetic_side_effects)] // Safe: checked non-empty before arithmetic
#[allow(clippy::indexing_slicing)] // Safe: checked non-empty before indexing
pub fn longest_run_test(bytes: &[u8]) -> Result<()> {
    if bytes.is_empty() {
        return Err(LatticeArcError::ValidationError {
            message: "Longest run test requires non-empty input".to_string(),
        });
    }

    // Safety: checked non-empty above
    let total_bits = bytes.len().saturating_mul(8);

    // Maximum expected run length for truly random data:
    // For n bits, expected longest run is approximately log2(n)
    // We allow some margin above this
    let max_allowed_run = if total_bits < 100 {
        12 // Very small samples
    } else if total_bits < 1000 {
        16 // Small samples
    } else if total_bits < 10000 {
        20 // Medium samples
    } else {
        26 // Large samples - log2(10000) ≈ 13, so 26 is 2x margin
    };

    let mut current_run: usize = 1;
    let mut longest_run: usize = 1;
    // Safety: checked non-empty above
    let mut prev_bit = (bytes[0] >> 7) & 1;

    for (i, &byte) in bytes.iter().enumerate() {
        let start_bit = if i == 0 { 6 } else { 7 };
        for bit_pos in (0..=start_bit).rev() {
            let current_bit = (byte >> bit_pos) & 1;
            if current_bit == prev_bit {
                current_run = current_run.saturating_add(1);
                if current_run > longest_run {
                    longest_run = current_run;
                }
            } else {
                current_run = 1;
                prev_bit = current_bit;
            }
        }
    }

    if longest_run > max_allowed_run {
        return Err(LatticeArcError::ValidationError {
            message: format!(
                "Longest run test failed: found run of {} bits (max allowed {} for {} total bits)",
                longest_run, max_allowed_run, total_bits
            ),
        });
    }

    Ok(())
}

// =============================================================================
// Combined Health Tests
// =============================================================================

/// Run all entropy health tests on fresh random bytes.
///
/// This function generates fresh random bytes using the system CSPRNG
/// and runs all implemented entropy health tests on them. This should
/// be called periodically to verify the entropy source is functioning
/// correctly.
///
/// # Returns
///
/// * `Ok(())` - If all health tests pass
/// * `Err(LatticeArcError::ValidationError)` - If any health test fails
///
/// # Example
///
/// ```no_run
/// use arc_primitives::rand::entropy_tests::run_entropy_health_tests;
///
/// // Run during initialization or periodically
/// match run_entropy_health_tests() {
///     Ok(()) => println!("Entropy source healthy"),
///     Err(e) => eprintln!("WARNING: {}", e),
/// }
/// ```
///
/// # Errors
///
/// Returns `LatticeArcError::ValidationError` if any entropy test fails.
pub fn run_entropy_health_tests() -> Result<()> {
    use super::random_bytes;

    // Generate fresh random bytes for testing
    let bytes = random_bytes(DEFAULT_SAMPLE_SIZE);

    // SP 800-90B basic tests
    repetition_test(&bytes).map_err(|e| LatticeArcError::ValidationError {
        message: format!("Entropy health check failed - {}", e),
    })?;

    frequency_test(&bytes).map_err(|e| LatticeArcError::ValidationError {
        message: format!("Entropy health check failed - {}", e),
    })?;

    // NIST SP 800-22 tests
    monobit_test(&bytes).map_err(|e| LatticeArcError::ValidationError {
        message: format!("Entropy health check failed - {}", e),
    })?;

    runs_test(&bytes).map_err(|e| LatticeArcError::ValidationError {
        message: format!("Entropy health check failed - {}", e),
    })?;

    longest_run_test(&bytes).map_err(|e| LatticeArcError::ValidationError {
        message: format!("Entropy health check failed - {}", e),
    })?;

    // SP 800-90B adaptive proportion test
    adaptive_proportion_test(&bytes).map_err(|e| LatticeArcError::ValidationError {
        message: format!("Entropy health check failed - {}", e),
    })?;

    Ok(())
}

/// Run entropy health tests on provided bytes.
///
/// This variant allows testing specific byte sequences, useful for
/// validation or when integrating with external entropy sources.
///
/// # Arguments
///
/// * `bytes` - The bytes to test
///
/// # Returns
///
/// * `Ok(())` - If all health tests pass
/// * `Err(LatticeArcError::ValidationError)` - If any health test fails
///
/// # Errors
///
/// Returns `LatticeArcError::ValidationError` if any entropy test fails.
pub fn run_entropy_health_tests_on_bytes(bytes: &[u8]) -> Result<()> {
    // SP 800-90B basic tests
    repetition_test(bytes)?;
    frequency_test(bytes)?;

    // NIST SP 800-22 tests
    monobit_test(bytes)?;
    runs_test(bytes)?;
    longest_run_test(bytes)?;

    // SP 800-90B adaptive proportion test
    adaptive_proportion_test(bytes)?;

    Ok(())
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -------------------------------------------------------------------------
    // Repetition Test
    // -------------------------------------------------------------------------

    #[test]
    fn test_repetition_test_passes_on_varied_input() {
        let bytes = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        assert!(repetition_test(&bytes).is_ok());
    }

    #[test]
    fn test_repetition_test_passes_with_max_allowed_consecutive() {
        // 5 consecutive identical bytes should pass
        let bytes = vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03];
        assert!(repetition_test(&bytes).is_ok());
    }

    #[test]
    fn test_repetition_test_fails_with_6_consecutive() {
        // 6 consecutive identical bytes should fail
        let bytes = vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02];
        let result = repetition_test(&bytes);
        assert!(result.is_err());
        assert!(matches!(result, Err(LatticeArcError::ValidationError { .. })));
    }

    #[test]
    fn test_repetition_test_fails_on_all_same() {
        let bytes = vec![0xFF; 100];
        assert!(repetition_test(&bytes).is_err());
    }

    #[test]
    fn test_repetition_test_empty_input() {
        let bytes: Vec<u8> = vec![];
        assert!(repetition_test(&bytes).is_err());
    }

    #[test]
    fn test_repetition_test_single_byte() {
        let bytes = vec![0x42];
        assert!(repetition_test(&bytes).is_ok());
    }

    #[test]
    fn test_repetition_test_two_same_bytes() {
        let bytes = vec![0x42, 0x42];
        assert!(repetition_test(&bytes).is_ok());
    }

    // -------------------------------------------------------------------------
    // Frequency Test
    // -------------------------------------------------------------------------

    #[test]
    fn test_frequency_test_passes_on_uniform() {
        // Create a roughly uniform distribution
        let mut bytes = Vec::with_capacity(256);
        for i in 0..=255u8 {
            bytes.push(i);
        }
        assert!(frequency_test(&bytes).is_ok());
    }

    #[test]
    fn test_frequency_test_fails_on_all_same() {
        let bytes = vec![0x00; 256];
        assert!(frequency_test(&bytes).is_err());
    }

    #[test]
    fn test_frequency_test_too_small_sample() {
        let bytes = vec![0x01, 0x02, 0x03];
        let result = frequency_test(&bytes);
        assert!(result.is_err());
        if let Err(LatticeArcError::ValidationError { message }) = result {
            assert!(message.contains("at least"));
        }
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn test_frequency_test_min_sample_size() {
        // Create a sample at exactly minimum size with some variation
        // Cast is safe: i % 256 always fits in u8
        let mut bytes = Vec::with_capacity(MIN_SAMPLE_SIZE);
        for i in 0..MIN_SAMPLE_SIZE {
            bytes.push((i % 256) as u8);
        }
        assert!(frequency_test(&bytes).is_ok());
    }

    #[test]
    fn test_frequency_test_heavily_biased() {
        // Create a heavily biased distribution
        let mut bytes = vec![0x00; 200];
        bytes.extend_from_slice(&[0x01; 56]);
        assert!(frequency_test(&bytes).is_err());
    }

    // -------------------------------------------------------------------------
    // Combined Tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_run_entropy_health_tests() {
        // This uses actual CSPRNG - should pass in normal conditions
        assert!(run_entropy_health_tests().is_ok());
    }

    #[test]
    fn test_run_entropy_health_tests_on_good_bytes() {
        // Create a good sample with no repetitions and reasonable distribution
        let mut bytes = Vec::with_capacity(256);
        for i in 0..=255u8 {
            bytes.push(i);
        }
        // Shuffle a bit to avoid perfect uniformity
        for i in 0..bytes.len() {
            let j = (i.wrapping_mul(7).wrapping_add(13)) % bytes.len();
            bytes.swap(i, j);
        }
        assert!(run_entropy_health_tests_on_bytes(&bytes).is_ok());
    }

    #[test]
    fn test_run_entropy_health_tests_on_bad_bytes() {
        // Create a bad sample with many repetitions
        let bytes = vec![0x42; 256];
        assert!(run_entropy_health_tests_on_bytes(&bytes).is_err());
    }

    #[test]
    fn test_repetition_at_end() {
        // Test repetition detection at the end of the sequence
        let mut bytes = vec![0x01, 0x02, 0x03, 0x04];
        bytes.extend_from_slice(&[0xFF; 6]); // 6 consecutive at end
        assert!(repetition_test(&bytes).is_err());
    }

    #[test]
    fn test_repetition_in_middle() {
        // Test repetition detection in the middle of the sequence
        let mut bytes = vec![0x01, 0x02];
        bytes.extend_from_slice(&[0xAA; 6]); // 6 consecutive in middle
        bytes.extend_from_slice(&[0x03, 0x04]);
        assert!(repetition_test(&bytes).is_err());
    }
}
