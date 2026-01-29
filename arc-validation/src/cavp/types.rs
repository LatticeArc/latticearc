#![deny(unsafe_code)]
#![allow(missing_docs)]
#![warn(clippy::unwrap_used)]
#![deny(clippy::panic)]
// JUSTIFICATION: CAVP (Cryptographic Algorithm Validation Program) test infrastructure.
// - Processes NIST test vectors with known-size binary data
// - Statistical calculations require floating-point arithmetic
// - Test code prioritizes correctness verification over panic-safety
#![allow(clippy::arithmetic_side_effects)]
#![allow(clippy::cast_precision_loss)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::indexing_slicing)]

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// CAVP test result with comprehensive metadata
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CavpTestResult {
    /// Unique test identifier
    pub test_id: String,
    /// Algorithm being tested
    pub algorithm: CavpAlgorithm,
    /// Test vector identifier
    pub vector_id: String,
    /// Whether test passed
    pub passed: bool,
    /// Execution time
    pub execution_time: Duration,
    /// Test timestamp
    pub timestamp: DateTime<Utc>,
    /// Actual result produced
    pub actual_result: Vec<u8>,
    /// Expected result from CAVP
    pub expected_result: Vec<u8>,
    /// Error message if test failed
    pub error_message: Option<String>,
    /// Additional metadata
    pub metadata: CavpTestMetadata,
}

/// Metadata for CAVP test results
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CavpTestMetadata {
    /// Test environment information
    pub environment: TestEnvironment,
    /// Security level tested
    pub security_level: usize,
    /// Test vector version
    pub vector_version: String,
    /// Implementation version
    pub implementation_version: String,
    /// Test configuration
    pub configuration: TestConfiguration,
}

impl Default for CavpTestMetadata {
    fn default() -> Self {
        Self {
            environment: TestEnvironment {
                os: std::env::consts::OS.to_string(),
                arch: std::env::consts::ARCH.to_string(),
                rust_version: env!("CARGO_PKG_RUST_VERSION").to_string(),
                compiler: "rustc".to_string(),
                framework_version: env!("CARGO_PKG_VERSION").to_string(),
            },
            security_level: 128,
            vector_version: "1.0".to_string(),
            implementation_version: env!("CARGO_PKG_VERSION").to_string(),
            configuration: TestConfiguration::default(),
        }
    }
}

/// Test environment information
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TestEnvironment {
    /// Operating system
    pub os: String,
    /// Architecture
    pub arch: String,
    /// Rust version
    pub rust_version: String,
    /// Compiler information
    pub compiler: String,
    /// Test framework version
    pub framework_version: String,
}

impl Default for TestEnvironment {
    fn default() -> Self {
        Self {
            os: std::env::consts::OS.to_string(),
            arch: std::env::consts::ARCH.to_string(),
            rust_version: "1.93.0".to_string(),
            compiler: "rustc".to_string(),
            framework_version: "1.0.0".to_string(),
        }
    }
}

/// Test configuration parameters
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TestConfiguration {
    /// Number of test iterations
    pub iterations: usize,
    /// Timeout per test
    pub timeout: Duration,
    /// Whether statistical tests were run
    pub statistical_tests: bool,
    /// Additional parameters
    pub parameters: std::collections::HashMap<String, Vec<u8>>,
}

impl Default for TestConfiguration {
    fn default() -> Self {
        Self {
            iterations: 1,
            timeout: Duration::from_secs(30),
            statistical_tests: false,
            parameters: std::collections::HashMap::new(),
        }
    }
}

/// CAVP algorithm identifier
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CavpAlgorithm {
    /// ML-KEM (Key Encapsulation Mechanism)
    MlKem { variant: String },
    /// ML-DSA (Digital Signature Algorithm)
    MlDsa { variant: String },
    /// SLH-DSA (Stateless Hash-Based Digital Signature Algorithm)
    SlhDsa { variant: String },
    /// FN-DSA (Falcon Number-Theoretic Digital Signature Algorithm)
    FnDsa { variant: String },
    /// Hybrid KEM
    HybridKem,
}

impl CavpAlgorithm {
    #[must_use]
    pub fn name(&self) -> String {
        match self {
            CavpAlgorithm::MlKem { variant } => format!("ML-KEM-{}", variant),
            CavpAlgorithm::MlDsa { variant } => format!("ML-DSA-{}", variant),
            CavpAlgorithm::SlhDsa { variant } => format!("SLH-DSA-{}", variant),
            CavpAlgorithm::FnDsa { variant } => format!("FN-DSA-{}", variant),
            CavpAlgorithm::HybridKem => "Hybrid-KEM".to_string(),
        }
    }

    #[must_use]
    pub fn fips_standard(&self) -> String {
        match self {
            CavpAlgorithm::MlKem { .. } => "FIPS 203".to_string(),
            CavpAlgorithm::MlDsa { .. } => "FIPS 204".to_string(),
            CavpAlgorithm::SlhDsa { .. } => "FIPS 205".to_string(),
            CavpAlgorithm::FnDsa { .. } => "FIPS 206".to_string(),
            CavpAlgorithm::HybridKem => "FIPS 203 + FIPS 197".to_string(),
        }
    }
}

/// CAVP test vector definition
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CavpTestVector {
    /// Vector identifier
    pub id: String,
    /// Algorithm this vector belongs to
    pub algorithm: CavpAlgorithm,
    /// Input parameters
    pub inputs: CavpVectorInputs,
    /// Expected outputs
    pub expected_outputs: CavpVectorOutputs,
    /// Vector metadata
    pub metadata: CavpVectorMetadata,
}

/// CAVP vector inputs
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CavpVectorInputs {
    /// Random seed for deterministic operations
    pub seed: Option<Vec<u8>>,
    /// Message to process (for signatures)
    pub message: Option<Vec<u8>>,
    /// Key material
    pub key_material: Option<Vec<u8>>,
    /// Public key for encryption/verification
    pub pk: Option<Vec<u8>>,
    /// Secret key for signing
    pub sk: Option<Vec<u8>>,
    /// Ciphertext for decryption
    pub c: Option<Vec<u8>>,
    /// Plaintext for encryption
    pub m: Option<Vec<u8>>,
    /// Public key for ECDH operations
    pub ek: Option<Vec<u8>>,
    /// Private key for ECDH operations
    pub dk: Option<Vec<u8>>,
    /// Signature for verification
    pub signature: Option<Vec<u8>>,
    /// Additional parameters specific to algorithm
    pub parameters: std::collections::HashMap<String, Vec<u8>>,
}

/// CAVP vector expected outputs
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CavpVectorOutputs {
    /// Expected public key
    pub public_key: Option<Vec<u8>>,
    /// Expected secret key
    pub secret_key: Option<Vec<u8>>,
    /// Expected ciphertext
    pub ciphertext: Option<Vec<u8>>,
    /// Expected signature
    pub signature: Option<Vec<u8>>,
    /// Expected shared secret
    pub shared_secret: Option<Vec<u8>>,
    /// Additional expected outputs
    pub additional: std::collections::HashMap<String, Vec<u8>>,
}

/// CAVP test types for different cryptographic operations
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CavpTestType {
    KeyGen,
    Encapsulation,
    Decapsulation,
    Signature,
    Verification,
}

/// CAVP vector metadata
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CavpVectorMetadata {
    /// Vector version
    pub version: String,
    /// Source (NIST, internal, etc.)
    pub source: String,
    /// Test type
    pub test_type: CavpTestType,
    /// Creation date
    pub created_at: DateTime<Utc>,
    /// Security classification
    pub security_level: usize,
    /// Additional notes
    pub notes: Option<String>,
}

/// CAVP validation status
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CavpValidationStatus {
    /// Validation passed
    Passed,
    /// Validation failed
    Failed,
    /// Validation incomplete
    Incomplete,
    /// Validation error
    Error(String),
}

/// CAVP batch test results
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CavpBatchResult {
    /// Batch identifier
    pub batch_id: String,
    /// Algorithm tested
    pub algorithm: CavpAlgorithm,
    /// Individual test results
    pub test_results: Vec<CavpTestResult>,
    /// Overall validation status
    pub status: CavpValidationStatus,
    /// Pass rate percentage
    pub pass_rate: f64,
    /// Total execution time
    pub total_execution_time: Duration,
    /// Batch timestamp
    pub timestamp: DateTime<Utc>,
}

impl CavpBatchResult {
    #[must_use]
    pub fn new(batch_id: String, algorithm: CavpAlgorithm) -> Self {
        Self {
            batch_id,
            algorithm,
            test_results: Vec::new(),
            status: CavpValidationStatus::Incomplete,
            pass_rate: 0.0,
            total_execution_time: Duration::ZERO,
            timestamp: Utc::now(),
        }
    }

    pub fn add_test_result(&mut self, result: CavpTestResult) {
        self.total_execution_time += result.execution_time;
        self.test_results.push(result);
        self.update_status();
    }

    pub fn update_status(&mut self) {
        if self.test_results.is_empty() {
            self.status = CavpValidationStatus::Incomplete;
            return;
        }

        let passed_tests = self.test_results.iter().filter(|r| r.passed).count();
        let total_tests = self.test_results.len();
        self.pass_rate = (passed_tests as f64 / total_tests as f64) * 100.0;

        self.status = if self.pass_rate >= 100.0 {
            CavpValidationStatus::Passed
        } else if self.pass_rate >= 0.0 {
            CavpValidationStatus::Failed
        } else {
            CavpValidationStatus::Error("Invalid pass rate calculation".to_string())
        };
    }
}

impl CavpTestResult {
    #[must_use]
    pub fn new(
        test_id: String,
        algorithm: CavpAlgorithm,
        vector_id: String,
        actual_result: Vec<u8>,
        expected_result: Vec<u8>,
        execution_time: Duration,
        metadata: CavpTestMetadata,
    ) -> Self {
        let passed = actual_result == expected_result;
        Self {
            test_id,
            algorithm,
            vector_id,
            passed,
            execution_time,
            timestamp: Utc::now(),
            actual_result,
            expected_result,
            error_message: None,
            metadata,
        }
    }

    #[must_use]
    #[allow(clippy::too_many_arguments)] // Constructor for test result with full context
    pub fn failed(
        test_id: String,
        algorithm: CavpAlgorithm,
        vector_id: String,
        actual_result: Vec<u8>,
        expected_result: Vec<u8>,
        execution_time: Duration,
        error_message: String,
        metadata: CavpTestMetadata,
    ) -> Self {
        Self {
            test_id,
            algorithm,
            vector_id,
            passed: false,
            execution_time,
            timestamp: Utc::now(),
            actual_result,
            expected_result,
            error_message: Some(error_message),
            metadata,
        }
    }
}
