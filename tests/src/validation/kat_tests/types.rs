#![deny(unsafe_code)]
#![allow(missing_docs)]
#![warn(clippy::unwrap_used)]
#![deny(clippy::panic)]
// JUSTIFICATION: KAT (Known Answer Test) type definitions.
// - Test result structures with statistical calculations
// - Binary data containers for test vectors
// - Test infrastructure prioritizes correctness verification
#![allow(clippy::arithmetic_side_effects)]
#![allow(clippy::cast_precision_loss)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::indexing_slicing)]

//! KAT (Known Answer Test) Types and Data Structures
//!
//! This module defines the data structures used for known answer testing
//! across all supported cryptographic algorithms.

use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Result of a KAT execution
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KatResult {
    /// Test case identifier
    pub test_case: String,
    /// Whether the test passed
    pub passed: bool,
    /// Execution time in nanoseconds
    pub execution_time_ns: u128,
    /// Error message if test failed
    pub error_message: Option<String>,
}

impl KatResult {
    /// Create a new successful KAT result
    #[must_use]
    pub fn passed(test_case: String, execution_time: Duration) -> Self {
        Self {
            test_case,
            passed: true,
            execution_time_ns: execution_time.as_nanos(),
            error_message: None,
        }
    }

    /// Create a new failed KAT result
    #[must_use]
    pub fn failed(test_case: String, execution_time: Duration, error: String) -> Self {
        Self {
            test_case,
            passed: false,
            execution_time_ns: execution_time.as_nanos(),
            error_message: Some(error),
        }
    }
}

/// ML-KEM Known Answer Test Vector
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MlKemKatVector {
    /// Test case identifier
    pub test_case: String,
    /// Random seed for key generation
    pub seed: Vec<u8>,
    /// Expected public key
    pub expected_public_key: Vec<u8>,
    /// Expected secret key
    pub expected_secret_key: Vec<u8>,
    /// Expected ciphertext
    pub expected_ciphertext: Vec<u8>,
    /// Expected shared secret
    pub expected_shared_secret: Vec<u8>,
}

/// ML-DSA Known Answer Test Vector
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MlDsaKatVector {
    /// Test case identifier
    pub test_case: String,
    /// Random seed for key generation
    pub seed: Vec<u8>,
    /// Message to sign
    pub message: Vec<u8>,
    /// Expected public key
    pub expected_public_key: Vec<u8>,
    /// Expected secret key
    pub expected_secret_key: Vec<u8>,
    /// Expected signature
    pub expected_signature: Vec<u8>,
}

/// SLH-DSA Known Answer Test Vector
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlhDsaKatVector {
    /// Test case identifier
    pub test_case: String,
    /// Random seed for key generation
    pub seed: Vec<u8>,
    /// Message to sign
    pub message: Vec<u8>,
    /// Expected public key
    pub expected_public_key: Vec<u8>,
    /// Expected signature
    pub expected_signature: Vec<u8>,
}

/// Hybrid KEM Known Answer Test Vector (X25519 + ML-KEM)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HybridKemKatVector {
    /// Test case identifier
    pub test_case: String,
    /// Random seed
    pub seed: Vec<u8>,
    /// Expected encapsulated key
    pub expected_encapsulated_key: Vec<u8>,
    /// Expected shared secret
    pub expected_shared_secret: Vec<u8>,
}

/// AES-GCM Known Answer Test Vector
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AesGcmKatVector {
    /// Test case identifier
    pub test_case: String,
    /// Encryption key
    pub key: Vec<u8>,
    /// Nonce/IV
    pub nonce: Vec<u8>,
    /// Additional authenticated data
    pub aad: Vec<u8>,
    /// Plaintext
    pub plaintext: Vec<u8>,
    /// Expected ciphertext
    pub expected_ciphertext: Vec<u8>,
    /// Expected authentication tag
    pub expected_tag: Vec<u8>,
}

/// SHA3 Known Answer Test Vector
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sha3KatVector {
    /// Test case identifier
    pub test_case: String,
    /// Input message
    pub message: Vec<u8>,
    /// Expected hash output
    pub expected_hash: Vec<u8>,
}

/// Ed25519 Known Answer Test Vector
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ed25519KatVector {
    /// Test case identifier
    pub test_case: String,
    /// Secret seed (32 bytes)
    pub seed: Vec<u8>,
    /// Expected public key (32 bytes)
    pub expected_public_key: Vec<u8>,
    /// Message to sign
    pub message: Vec<u8>,
    /// Expected signature (64 bytes)
    pub expected_signature: Vec<u8>,
}

/// BLS12-381 Known Answer Test Vector (G1/G2 points)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bls12_381KatVector {
    /// Test case identifier
    pub test_case: String,
    /// Secret key
    pub secret_key: Vec<u8>,
    /// Expected public key (G1 point)
    pub expected_public_key: Vec<u8>,
    /// Message to sign
    pub message: Vec<u8>,
    /// Expected signature (G2 point)
    pub expected_signature: Vec<u8>,
}

/// BN254 Known Answer Test Vector
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bn254KatVector {
    /// Test case identifier
    pub test_case: String,
    /// Secret key
    pub secret_key: Vec<u8>,
    /// Expected public key
    pub expected_public_key: Vec<u8>,
    /// Message to sign
    pub message: Vec<u8>,
    /// Expected signature
    pub expected_signature: Vec<u8>,
}

/// Secp256k1 Known Answer Test Vector
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Secp256k1KatVector {
    /// Test case identifier
    pub test_case: String,
    /// Private key
    pub private_key: Vec<u8>,
    /// Expected public key
    pub expected_public_key: Vec<u8>,
    /// Message to sign
    pub message: Vec<u8>,
    /// Expected DER signature
    pub expected_signature: Vec<u8>,
}

/// NIST Statistical Test Results
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NistStatisticalTestResult {
    /// Test name
    pub test_name: String,
    /// P-value from the test
    pub p_value: f64,
    /// Whether the test passed (p-value > 0.01 typically)
    pub passed: bool,
    /// Test parameters
    pub parameters: serde_json::Value,
}

/// Random Number Generation Test Results
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RngTestResults {
    /// Algorithm being tested
    pub algorithm: String,
    /// Number of bits tested
    pub bits_tested: usize,
    /// Individual NIST test results
    pub test_results: Vec<NistStatisticalTestResult>,
    /// Overall assessment
    pub passed: bool,
    /// Sample entropy estimate
    pub entropy_estimate: f64,
}

/// Algorithm identifier for KAT testing
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AlgorithmType {
    /// ML-KEM (Key Encapsulation Mechanism)
    MlKem { variant: String },
    /// ML-DSA (Digital Signature Algorithm)
    MlDsa { variant: String },
    /// SLH-DSA (Stateless Hash-Based Digital Signature Algorithm)
    SlhDsa { variant: String },
    /// Hybrid KEM
    HybridKem,
    /// AES-GCM (Authenticated Encryption)
    AesGcm { key_size: usize },
    /// SHA3 (Hash Function)
    Sha3 { variant: String },
    /// Ed25519 (Elliptic Curve Digital Signature Algorithm)
    Ed25519,
    /// BLS12-381 (Pairing-based Cryptography)
    Bls12_381,
    /// BN254 (Pairing-based Cryptography)
    Bn254,
    /// Secp256k1 (Elliptic Curve)
    Secp256k1,
}

impl AlgorithmType {
    /// Get the standard name for the algorithm
    #[must_use]
    pub fn name(&self) -> String {
        match self {
            AlgorithmType::MlKem { variant } => format!("ML-KEM-{}", variant),
            AlgorithmType::MlDsa { variant } => format!("ML-DSA-{}", variant),
            AlgorithmType::SlhDsa { variant } => format!("SLH-DSA-{}", variant),
            AlgorithmType::HybridKem => "Hybrid-KEM".to_string(),
            AlgorithmType::AesGcm { key_size } => format!("AES-{}-GCM", key_size * 8),
            AlgorithmType::Sha3 { variant } => format!("SHA3-{}", variant),
            AlgorithmType::Ed25519 => "Ed25519".to_string(),
            AlgorithmType::Bls12_381 => "BLS12-381".to_string(),
            AlgorithmType::Bn254 => "BN254".to_string(),
            AlgorithmType::Secp256k1 => "secp256k1".to_string(),
        }
    }

    /// Get the security level in bits
    #[must_use]
    pub fn security_level(&self) -> usize {
        match self {
            AlgorithmType::MlKem { variant } => match variant.as_str() {
                "512" => 128,
                "768" => 192,
                "1024" => 256,
                _ => 128,
            },
            AlgorithmType::MlDsa { variant } => match variant.as_str() {
                "44" => 128,
                "65" => 192,
                "87" => 256,
                _ => 128,
            },
            AlgorithmType::SlhDsa { variant } => match variant.as_str() {
                "128" => 128,
                "192" => 192,
                "256" => 256,
                _ => 128,
            },
            AlgorithmType::HybridKem => 256, // X25519 (128) + ML-KEM-1024 (256)
            AlgorithmType::AesGcm { key_size } => key_size * 8,
            AlgorithmType::Sha3 { variant } => variant.parse().unwrap_or(256),
            AlgorithmType::Ed25519 => 128,
            AlgorithmType::Bls12_381 => 128,
            AlgorithmType::Bn254 => 128,
            AlgorithmType::Secp256k1 => 128,
        }
    }
}

/// KAT Test Configuration
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KatConfig {
    /// Algorithm to test
    pub algorithm: AlgorithmType,
    /// Number of test vectors to run
    pub test_count: usize,
    /// Whether to run statistical tests on generated randomness
    pub run_statistical_tests: bool,
    /// Timeout for individual test cases
    pub timeout_per_test: Duration,
    /// Whether to validate FIPS compliance
    pub validate_fips: bool,
}

impl Default for KatConfig {
    fn default() -> Self {
        Self {
            algorithm: AlgorithmType::MlKem { variant: "768".to_string() },
            test_count: 100,
            run_statistical_tests: true,
            timeout_per_test: Duration::from_secs(10),
            validate_fips: true,
        }
    }
}

impl KatConfig {
    /// Create config for ML-KEM testing
    #[must_use]
    pub fn ml_kem(variant: &str, test_count: usize) -> Self {
        Self {
            algorithm: AlgorithmType::MlKem { variant: variant.to_string() },
            test_count,
            run_statistical_tests: true,
            timeout_per_test: Duration::from_secs(10),
            validate_fips: true,
        }
    }

    /// Create config for ML-DSA testing
    #[must_use]
    pub fn ml_dsa(variant: &str, test_count: usize) -> Self {
        Self {
            algorithm: AlgorithmType::MlDsa { variant: variant.to_string() },
            test_count,
            run_statistical_tests: true,
            timeout_per_test: Duration::from_secs(10),
            validate_fips: true,
        }
    }

    /// Create config for SLH-DSA testing
    #[must_use]
    pub fn slh_dsa(variant: &str, test_count: usize) -> Self {
        Self {
            algorithm: AlgorithmType::SlhDsa { variant: variant.to_string() },
            test_count,
            run_statistical_tests: true,
            timeout_per_test: Duration::from_secs(30), // SLH-DSA is slower
            validate_fips: true,
        }
    }
}
