#![deny(unsafe_code)]
#![allow(missing_docs)]
#![warn(clippy::unwrap_used)]
#![deny(clippy::panic)]
// JUSTIFICATION: Test result counters - overflow is impossible with realistic test counts
#![allow(clippy::arithmetic_side_effects)]
// JUSTIFICATION: Test code uses expect() for known-valid test vectors and println! for test output
#![allow(clippy::expect_used)]
#![allow(clippy::print_stdout)]

//! NIST Known Answer Test (KAT) Framework
//!
//! This module provides a comprehensive framework for validating cryptographic
//! implementations against official NIST test vectors and RFC specifications.
//!
//! ## Supported Standards
//!
//! ### NIST Standards
//! - FIPS 203: ML-KEM (Module-Lattice-Based Key Encapsulation Mechanism)
//! - FIPS 204: ML-DSA (Module-Lattice-Based Digital Signature Algorithm)
//! - SP 800-38D: AES-GCM (Galois/Counter Mode)
//! - FIPS 180-4: SHA-2 Family
//!
//! ### RFC Standards
//! - RFC 5869: HKDF (HMAC-based Key Derivation Function)
//! - RFC 4231: HMAC Test Vectors
//! - RFC 8439: ChaCha20-Poly1305 AEAD
//! - RFC 7748: X25519 Elliptic Curve Diffie-Hellman
//! - RFC 8032: Ed25519 Digital Signatures
//!
//! ## Test Vector Format
//!
//! All test vectors are embedded in the source code as hex-encoded strings.
//! This ensures:
//! - Reproducibility across all platforms
//! - No runtime network dependencies
//! - Cryptographically verifiable test data
//! - Compliance with FIPS 140-3 requirements

pub mod aes_gcm_kat;
pub mod chacha20_poly1305_kat;
pub mod hkdf_kat;
pub mod hmac_kat;
pub mod ml_dsa_kat;
pub mod ml_kem_kat;
pub mod runner;
pub mod sha2_kat;

pub use runner::{KatRunner, KatSummary};

use thiserror::Error;

/// Errors from NIST KAT execution
#[derive(Debug, Error)]
pub enum NistKatError {
    /// Test vector validation failed
    #[error("KAT failed: {algorithm} - {test_name}: {message}")]
    TestFailed {
        /// Algorithm name
        algorithm: String,
        /// Test name
        test_name: String,
        /// Failure message
        message: String,
    },

    /// Hex decoding error
    #[error("Hex decode error: {0}")]
    HexError(String),

    /// Implementation error
    #[error("Implementation error: {0}")]
    ImplementationError(String),

    /// Unsupported algorithm
    #[error("Unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),
}

/// Result of running a single KAT test
#[derive(Debug, Clone)]
pub struct KatTestResult {
    /// Test case identifier
    pub test_case: String,
    /// Algorithm being tested
    pub algorithm: String,
    /// Whether the test passed
    pub passed: bool,
    /// Error message if test failed
    pub error_message: Option<String>,
    /// Test execution time in microseconds
    pub execution_time_us: u128,
}

impl KatTestResult {
    /// Create a passed test result
    #[must_use]
    pub fn passed(test_case: String, algorithm: String, execution_time_us: u128) -> Self {
        Self { test_case, algorithm, passed: true, error_message: None, execution_time_us }
    }

    /// Create a failed test result
    #[must_use]
    pub fn failed(
        test_case: String,
        algorithm: String,
        error: String,
        execution_time_us: u128,
    ) -> Self {
        Self { test_case, algorithm, passed: false, error_message: Some(error), execution_time_us }
    }
}

/// Helper function to decode hex strings
///
/// # Errors
///
/// Returns `NistKatError::HexError` if the input string is not valid hex.
pub fn decode_hex(s: &str) -> Result<Vec<u8>, NistKatError> {
    hex::decode(s).map_err(|e| NistKatError::HexError(e.to_string()))
}
