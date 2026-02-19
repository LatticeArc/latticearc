//! # arc-tests
//!
//! Comprehensive test suite for LatticeArc providing:
//!
//! - **Regression Tests**: Prevent reintroduction of fixed bugs
//! - **API Stability Tests**: Ensure backward compatibility across versions
//! - **Concurrency Tests**: Verify thread-safe operation
//!
//! ## Running Tests
//!
//! ```bash
//! # Run all tests
//! cargo test -p arc-tests
//!
//! # Run specific category
//! cargo test -p arc-tests regression
//! cargo test -p arc-tests api_stability
//! cargo test -p arc-tests concurrency
//! ```
//!
//! ## Adding Regression Tests
//!
//! Each regression test should:
//! 1. Be in its own file: `src/regression/issue_NNN_description.rs`
//! 2. Include a doc comment linking to the original issue
//! 3. Reproduce the exact bug condition
//! 4. Verify the fix works
//!
//! ## Test Naming Convention
//!
//! - Regression: `regression_issue_NNN_description`
//! - API Stability: `api_stability_<aspect>_<test>`
//! - Concurrency: `concurrent_<operation>_<scenario>`

#![allow(clippy::expect_used)] // Tests use expect for clarity

pub mod api_stability;
pub mod concurrency;
pub mod regression;
/// FIPS validation, CAVP compliance, and KAT testing
pub mod validation;

/// Shared test utilities
pub mod utils {
    use rand::rngs::OsRng;

    /// Get a cryptographically secure RNG for tests
    #[must_use]
    pub fn test_rng() -> OsRng {
        OsRng
    }

    /// Assert two byte slices are equal with descriptive message
    ///
    /// # Panics
    ///
    /// Panics if `left` and `right` are not equal, displaying the provided `context`.
    pub fn assert_bytes_eq(left: &[u8], right: &[u8], context: &str) {
        assert_eq!(left, right, "{}: byte slices differ at first mismatch", context);
    }

    /// Assert two byte slices are NOT equal
    ///
    /// # Panics
    ///
    /// Panics if `left` and `right` are equal, displaying the provided `context`.
    pub fn assert_bytes_ne(left: &[u8], right: &[u8], context: &str) {
        assert_ne!(left, right, "{}: byte slices should differ", context);
    }
}

#[cfg(test)]
mod tests {
    use super::utils;

    #[test]
    fn test_rng_returns_osrng() {
        use rand::RngCore;
        let mut rng = utils::test_rng();
        let mut buf = [0u8; 16];
        rng.fill_bytes(&mut buf);
        // Should produce non-zero random bytes
        assert!(buf.iter().any(|&b| b != 0), "RNG should produce non-zero output");
    }

    #[test]
    fn test_assert_bytes_eq_matching() {
        utils::assert_bytes_eq(b"hello", b"hello", "matching slices");
        utils::assert_bytes_eq(&[], &[], "empty slices");
        utils::assert_bytes_eq(&[1, 2, 3], &[1, 2, 3], "numeric slices");
    }

    #[test]
    #[should_panic(expected = "byte slices differ")]
    fn test_assert_bytes_eq_mismatch() {
        utils::assert_bytes_eq(b"hello", b"world", "should panic");
    }

    #[test]
    fn test_assert_bytes_ne_different() {
        utils::assert_bytes_ne(b"hello", b"world", "different slices");
        utils::assert_bytes_ne(&[1], &[2], "single byte diff");
    }

    #[test]
    #[should_panic(expected = "byte slices should differ")]
    fn test_assert_bytes_ne_same() {
        utils::assert_bytes_ne(b"same", b"same", "should panic");
    }
}
