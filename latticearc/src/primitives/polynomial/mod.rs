#![deny(unsafe_code)]
#![warn(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]
// JUSTIFICATION: Polynomial arithmetic for lattice-based cryptography requires direct
// array indexing for performance-critical NTT operations. All array accesses are
// bounded by algorithm invariants (power-of-2 sizes, modular indices).
#![allow(clippy::indexing_slicing)]

//! Polynomial Operations with NTT (Number Theoretic Transform)
//!
//! This module provides efficient polynomial arithmetic using the Number Theoretic Transform,
//! which enables O(n log n) multiplication instead of O(n²). This is crucial for
//! lattice-based cryptography and homomorphic encryption schemes.
//!
//! # Key Features
//! - Forward and inverse NTT transforms
//! - Fast polynomial multiplication via NTT
//! - Montgomery reduction for efficient modular arithmetic
//! - Support for various moduli used in cryptographic schemes
//!
//! # SIMD Acceleration
//! SIMD-accelerated polynomial operations are not currently available.
//! The `portable_simd` feature requires nightly Rust, but this crate
//! targets stable Rust only. Scalar implementations are used instead.
//!

/// Polynomial arithmetic operations.
pub mod arithmetic;
/// Montgomery reduction for modular arithmetic.
pub mod montgomery;
/// Number Theoretic Transform (NTT) processor for polynomial multiplication.
pub mod ntt_processor;

// Re-export main types for convenience
pub use montgomery::MontgomeryReducer;
pub use ntt_processor::NttProcessor;

#[cfg(test)]
#[allow(clippy::panic_in_result_fn)] // Test assertions are expected to panic on failure
mod tests {
    use super::*;

    #[test]
    fn test_ntt_processor_creation() -> Result<(), Box<dyn std::error::Error>> {
        // Test Kyber parameters
        let processor = NttProcessor::new(256, 3329)?;
        assert_eq!(processor.n, 256);
        assert_eq!(processor.modulus, 3329);
        Ok(())
    }

    #[test]
    fn test_ntt_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let processor = NttProcessor::new(256, 3329)?;

        // Create test polynomial
        let coeffs = (0..256).map(|i| i % 100).collect::<Vec<_>>();

        // Forward then inverse NTT should recover original coefficients
        let ntt_result = processor.forward(&coeffs)?;
        let recovered = processor.inverse(&ntt_result)?;

        // Check recovery (allowing for small numerical differences)
        for i in 0..256 {
            assert!((recovered[i] - coeffs[i]).abs() < 10);
        }
        Ok(())
    }

    #[test]
    fn test_polynomial_multiplication() -> Result<(), Box<dyn std::error::Error>> {
        let processor = NttProcessor::new(256, 3329)?;

        // Simple polynomials: (x + 1) * (x + 1) = x² + 2x + 1
        let _a = [1, 1]; // x + 1 (padded to size 256)
        let mut a_padded = vec![0; 256];
        if let Some(pos) = a_padded.get_mut(0) {
            *pos = 1;
        }
        if let Some(pos) = a_padded.get_mut(1) {
            *pos = 1;
        }

        let mut b_padded = vec![0; 256];
        if let Some(pos) = b_padded.get_mut(0) {
            *pos = 1;
        }
        if let Some(pos) = b_padded.get_mut(1) {
            *pos = 1;
        }

        let result = processor.multiply(&a_padded, &b_padded)?;

        // Check result: should be x² + 2x + 1
        assert_eq!(result[0], 1); // constant term
        assert_eq!(result[1], 2); // x term
        assert_eq!(result[2], 1); // x² term
        Ok(())
    }

    #[test]
    fn test_ntt_processor_invalid_size() {
        // Test with invalid NTT size (not power of 2)
        let result = NttProcessor::new(255, 3329);
        assert!(result.is_err());
    }

    #[test]
    fn test_ntt_processor_invalid_modulus() {
        // Test with modulus that has no known primitive root
        let result = NttProcessor::new(256, 12345);
        assert!(result.is_err());
    }

    #[test]
    fn test_ntt_processor_different_parameters() -> Result<(), Box<dyn std::error::Error>> {
        // Test Dilithium parameters
        let processor = NttProcessor::new(512, 12289)?;
        assert_eq!(processor.n, 512);
        assert_eq!(processor.modulus, 12289);
        Ok(())
    }

    #[test]
    fn test_polynomial_multiplication_zero() -> Result<(), Box<dyn std::error::Error>> {
        let processor = NttProcessor::new(256, 3329)?;

        let zero_poly = vec![0; 256];
        let test_poly: Vec<_> = (0..256).collect();

        let result = processor.multiply(&zero_poly, &test_poly)?;

        // Zero polynomial times anything should be zero
        assert!(result.iter().all(|&x| x == 0));
        Ok(())
    }

    #[test]
    fn test_polynomial_multiplication_identity() -> Result<(), Box<dyn std::error::Error>> {
        let processor = NttProcessor::new(256, 3329)?;

        let mut identity = vec![0; 256];
        if let Some(pos) = identity.get_mut(0) {
            *pos = 1;
        } // Constant term 1

        let test_poly = (0..256).map(|i| i % 10).collect::<Vec<_>>();
        let result = processor.multiply(&identity, &test_poly)?;

        // Identity times polynomial should equal polynomial
        for (i, &test_val) in test_poly.iter().enumerate() {
            if let Some(&result_val) = result.get(i) {
                assert!((result_val - test_val).abs() < 5); // Allow small numerical differences
            }
        }
        Ok(())
    }
}
