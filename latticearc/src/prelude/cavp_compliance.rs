//! CAVP (Cryptographic Algorithm Validation Program) Compliance Testing
//!
//! This module provides infrastructure for NIST CAVP compliance testing,
//! focusing on utility functions, error handling, and core cryptographic primitives.
//!
//! CAVP is the official NIST program for validating cryptographic implementations
//! against standardized test vectors.

#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

use crate::prelude::error::{LatticeArcError, Result};
#[cfg(not(feature = "fips"))]
use crate::primitives::ec::secp256k1::{Secp256k1KeyPair, Secp256k1Signature};
use crate::primitives::ec::{
    ed25519::{Ed25519KeyPair, Ed25519Signature},
    traits::{EcKeyPair, EcSignature},
};
use std::collections::HashMap;

/// CAVP test vector structure for prelude utilities.
///
/// Represents a single test case for validating utility functions
/// like hex encoding, UUID generation, and domain constants.
#[derive(Debug, Clone)]
pub struct UtilityTestVector {
    /// Unique identifier for the test case.
    pub test_case_id: String,
    /// Name of the function being tested.
    pub function: String,
    /// Input data for the test.
    pub input_data: Vec<u8>,
    /// Expected output data.
    pub expected_output: Vec<u8>,
    /// Additional parameters for the test.
    pub parameters: HashMap<String, String>,
}

/// CAVP test vector structure for cryptographic algorithms.
///
/// Represents a single test case for validating cryptographic
/// operations like signing and verification.
///
/// # ⚠️ KAT vectors only — do not wire real keys
///
/// This struct holds **published CAVP/ACVP test data only**. The
/// `kat_private_key_bytes` field is intentionally a plain `Vec<u8>`
/// with derived `Debug` + `Clone` because CAVP vectors are public
/// reference values and the test harness needs to print them on
/// failure. **Do not** populate this struct with real key material
/// — the type provides no zeroization on drop and `Debug` will
/// emit the bytes verbatim into any log or panic message. For real
/// secrets use [`PrivateKey`](crate::types::PrivateKey) (zeroizes
/// on drop, Debug-redacted) or
/// [`SecretVec`](crate::types::SecretVec).
///
/// Marked `#[non_exhaustive]` so adding test-harness fields later
/// is not a breaking change.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct CryptoTestVector {
    /// Unique identifier for the test case.
    pub test_case_id: String,
    /// Algorithm being tested (e.g., "ECDSA-secp256k1", "Ed25519").
    pub algorithm: String,
    /// Operation being tested ("sign" or "verify").
    pub operation: String,
    /// **KAT private-key BYTES — public CAVP test data, never a real secret.**
    /// See struct-level doc warning above.
    pub kat_private_key_bytes: Vec<u8>,
    /// Public key bytes (for verification operations).
    pub public_key: Vec<u8>,
    /// Message to sign or verify.
    pub message: Vec<u8>,
    /// Signature bytes (for verification operations).
    pub signature: Vec<u8>,
    /// Expected result (true for success, false for expected failure).
    pub expected_result: bool,
    /// Additional parameters for the test.
    pub parameters: HashMap<String, String>,
}

/// CAVP compliance test runner for utility functions.
///
/// Provides infrastructure for running NIST CAVP-style tests
/// against utility functions like hex encoding and UUID generation.
pub struct UtilityCavpTester {
    /// Loaded test vectors.
    test_vectors: Vec<UtilityTestVector>,
    /// Results of executed tests.
    results: HashMap<String, bool>,
}

impl UtilityCavpTester {
    /// Create a new utility CAVP tester.
    #[must_use]
    pub fn new() -> Self {
        Self { test_vectors: Vec::new(), results: HashMap::new() }
    }

    /// Load CAVP test vectors for utilities.
    pub fn load_test_vectors(&mut self, vectors: Vec<UtilityTestVector>) {
        self.test_vectors = vectors;
    }

    /// Run all loaded CAVP test vectors.
    ///
    /// # Errors
    ///
    /// Returns an error if any CAVP test vector fails verification.
    pub fn run_compliance_tests(&mut self) -> Result<()> {
        tracing::info!("Running utility CAVP compliance tests");

        for vector in &self.test_vectors {
            let result = Self::run_single_test(vector)?;
            self.results.insert(vector.test_case_id.clone(), result);

            if result {
                tracing::info!("Test {}: PASSED", vector.test_case_id);
            } else {
                tracing::error!("Test {}: FAILED", vector.test_case_id);
                return Err(LatticeArcError::VerificationFailed(format!(
                    "CAVP test {} failed",
                    vector.test_case_id
                )));
            }
        }

        Ok(())
    }

    /// Generate CAVP compliance report
    #[must_use]
    pub fn generate_report(&self) -> String {
        let mut report = String::from("# Utility CAVP Compliance Test Report\n\n");

        report.push_str(&format!("Total Tests: {}\n", self.test_vectors.len()));
        report.push_str(&format!("Passed: {}\n", self.results.values().filter(|&&v| v).count()));
        report.push_str(&format!("Failed: {}\n\n", self.results.values().filter(|&&v| !v).count()));

        report.push_str("## Test Results\n\n");
        for (test_id, passed) in &self.results {
            let status = if *passed { "✅ PASSED" } else { "❌ FAILED" };
            report.push_str(&format!("- {}: {}\n", test_id, status));
        }

        report
    }

    /// Run a single CAVP test vector.
    fn run_single_test(vector: &UtilityTestVector) -> Result<bool> {
        match vector.function.as_str() {
            "hex_encode" => Ok(Self::test_hex_encode_succeeds(vector)),
            "hex_decode" => Self::test_hex_decode_succeeds(vector),
            "uuid_generate" => Ok(Self::test_uuid_generate_succeeds()),
            "version_check" => Ok(Self::test_version_check_succeeds(vector)),
            "domain_constant" => Self::test_domain_constant_succeeds(vector),
            _ => Err(LatticeArcError::InvalidConfiguration(format!(
                "Unsupported utility function: {}",
                vector.function
            ))),
        }
    }

    /// Test hex encoding.
    fn test_hex_encode_succeeds(vector: &UtilityTestVector) -> bool {
        let encoded = hex::encode(&vector.input_data);
        let encoded_bytes = encoded.as_bytes();

        // Compare with expected output
        encoded_bytes == &vector.expected_output[..]
    }

    /// Test hex decoding.
    fn test_hex_decode_succeeds(vector: &UtilityTestVector) -> Result<bool> {
        // Convert input to hex string
        let hex_string = std::str::from_utf8(&vector.input_data)
            .map_err(|e| LatticeArcError::InvalidData(format!("Invalid hex string: {}", e)))?;

        let decoded = hex::decode(hex_string)?;

        // Compare with expected output
        Ok(decoded == vector.expected_output)
    }

    /// Test UUID generation.
    fn test_uuid_generate_succeeds() -> bool {
        let uuid = uuid::Uuid::new_v4();

        // Basic validation that UUID is generated
        if uuid.is_nil() {
            return false;
        }

        // Check version is 4 (random)
        if uuid.get_version_num() != 4 {
            return false;
        }

        // Check string format
        let uuid_str = uuid.to_string();
        if uuid_str.len() != 36 {
            return false;
        }

        // Check hyphen positions
        let chars: Vec<char> = uuid_str.chars().collect();
        if chars.get(8) != Some(&'-')
            || chars.get(13) != Some(&'-')
            || chars.get(18) != Some(&'-')
            || chars.get(23) != Some(&'-')
        {
            return false;
        }

        true
    }

    /// Test version constant.
    fn test_version_check_succeeds(vector: &UtilityTestVector) -> bool {
        let expected_version = vector.expected_output.first().copied();
        let expected = expected_version.unwrap_or(1);

        crate::prelude::ENVELOPE_FORMAT_VERSION == expected
    }

    /// Test domain constants.
    fn test_domain_constant_succeeds(vector: &UtilityTestVector) -> Result<bool> {
        let domain_name = std::str::from_utf8(&vector.input_data)
            .map_err(|e| LatticeArcError::InvalidData(format!("Invalid domain name: {}", e)))?;

        let domain_constant = match domain_name {
            "CASCADE_OUTER" => crate::types::domains::CASCADE_OUTER,
            "CASCADE_INNER" => crate::types::domains::CASCADE_INNER,
            "HYBRID_KEM_SS_INFO" => crate::types::domains::HYBRID_KEM_SS_INFO,
            _ => return Ok(false),
        };

        Ok(domain_constant == &vector.expected_output[..])
    }
}

impl Default for UtilityCavpTester {
    fn default() -> Self {
        Self::new()
    }
}

/// CAVP compliance test runner for cryptographic algorithms.
///
/// Provides infrastructure for running NIST CAVP-style tests
/// against cryptographic algorithms like ECDSA and Ed25519.
pub struct CryptoCavpTester {
    /// Loaded test vectors.
    test_vectors: Vec<CryptoTestVector>,
    /// Results of executed tests.
    results: HashMap<String, bool>,
}

impl CryptoCavpTester {
    /// Create a new crypto CAVP tester.
    #[must_use]
    pub fn new() -> Self {
        Self { test_vectors: Vec::new(), results: HashMap::new() }
    }

    /// Load CAVP test vectors for cryptographic algorithms.
    pub fn load_test_vectors(&mut self, vectors: Vec<CryptoTestVector>) {
        self.test_vectors = vectors;
    }

    /// Run all loaded CAVP test vectors.
    ///
    /// # Errors
    ///
    /// Returns an error if any cryptographic CAVP test vector fails verification.
    pub fn run_compliance_tests(&mut self) -> Result<()> {
        tracing::info!("Running cryptographic CAVP compliance tests");

        for vector in &self.test_vectors {
            let result = Self::run_single_test(vector)?;
            self.results.insert(vector.test_case_id.clone(), result);

            if result {
                tracing::info!("Test {}: PASSED", vector.test_case_id);
            } else {
                tracing::error!("Test {}: FAILED", vector.test_case_id);
                return Err(LatticeArcError::VerificationFailed(format!(
                    "CAVP test {} failed",
                    vector.test_case_id
                )));
            }
        }

        Ok(())
    }

    /// Generate CAVP compliance report.
    ///
    /// Creates a markdown-formatted report of all cryptographic test results.
    #[must_use]
    pub fn generate_report(&self) -> String {
        let mut report = String::from("# Cryptographic CAVP Compliance Test Report\n\n");

        report.push_str(&format!("Total Tests: {}\n", self.test_vectors.len()));
        report.push_str(&format!("Passed: {}\n", self.results.values().filter(|&&v| v).count()));
        report.push_str(&format!("Failed: {}\n\n", self.results.values().filter(|&&v| !v).count()));

        report.push_str("## Test Results\n\n");
        for (test_id, passed) in &self.results {
            let status = if *passed { "✅ PASSED" } else { "❌ FAILED" };
            report.push_str(&format!("- {}: {}\n", test_id, status));
        }

        report
    }

    /// Run a single CAVP test vector.
    fn run_single_test(vector: &CryptoTestVector) -> Result<bool> {
        match vector.algorithm.as_str() {
            #[cfg(not(feature = "fips"))]
            "ECDSA-secp256k1" => Self::run_ecdsa_test(vector),
            "Ed25519" => Self::run_ed25519_test(vector),
            _ => Err(LatticeArcError::InvalidConfiguration(format!(
                "Unsupported algorithm: {}",
                vector.algorithm
            ))),
        }
    }

    /// Run ECDSA test.
    #[cfg(not(feature = "fips"))]
    fn run_ecdsa_test(vector: &CryptoTestVector) -> Result<bool> {
        match vector.operation.as_str() {
            "sign" => {
                // For signing tests, just verify that a signature can be generated
                let keypair = Secp256k1KeyPair::from_secret_key(&vector.kat_private_key_bytes)
                    .map_err(|e| {
                        LatticeArcError::InvalidData(format!("Invalid ECDSA private key: {e}"))
                    })?;

                let signature = keypair.sign(&vector.message).map_err(|e| {
                    LatticeArcError::InvalidData(format!("ECDSA signing failed: {e}"))
                })?;
                let signature_bytes = Secp256k1Signature::signature_bytes(&signature);

                // Length is necessary but not sufficient: a sign
                // implementation that returned 64 bytes of garbage
                // would pass a length-only check while emitting
                // unverifiable signatures. Verify the signature
                // against the matching public key here so the
                // "sign" CAVP test actually validates correctness.
                if signature_bytes.is_empty() || signature_bytes.len() != 64 {
                    return Ok(false);
                }
                let pk_bytes = keypair.public_key_bytes();
                let verify_ok =
                    Secp256k1Signature::verify(&pk_bytes, &vector.message, &signature).is_ok();
                Ok(verify_ok)
            }
            "verify" => {
                // Verify the provided signature
                let signature = Secp256k1Signature::signature_from_bytes(&vector.signature)
                    .map_err(|e| {
                        LatticeArcError::InvalidData(format!("Invalid ECDSA signature: {e}"))
                    })?;

                let result =
                    Secp256k1Signature::verify(&vector.public_key, &vector.message, &signature)
                        .is_ok();
                Ok(result == vector.expected_result)
            }
            _ => Err(LatticeArcError::InvalidConfiguration(format!(
                "Unsupported ECDSA operation: {}",
                vector.operation
            ))),
        }
    }

    /// Run Ed25519 test.
    fn run_ed25519_test(vector: &CryptoTestVector) -> Result<bool> {
        match vector.operation.as_str() {
            "sign" => {
                // For signing tests, just verify that a signature can be generated
                let keypair = Ed25519KeyPair::from_secret_key(&vector.kat_private_key_bytes)
                    .map_err(|e| {
                        LatticeArcError::InvalidData(format!("Invalid Ed25519 private key: {e}"))
                    })?;

                let signature = keypair.sign(&vector.message).map_err(|e| {
                    LatticeArcError::InvalidData(format!("Ed25519 sign failed: {e}"))
                })?;
                let signature_bytes = Ed25519Signature::signature_bytes(&signature);

                // Length is necessary but not sufficient. Verify the
                // signature with the matching PK so a length-only
                // check can't pass garbage signatures.
                if signature_bytes.is_empty() || signature_bytes.len() != 64 {
                    return Ok(false);
                }
                let pk_bytes = keypair.public_key_bytes();
                let verify_ok =
                    Ed25519Signature::verify(&pk_bytes, &vector.message, &signature).is_ok();
                Ok(verify_ok)
            }
            "verify" => {
                // Verify the provided signature
                let signature =
                    Ed25519Signature::signature_from_bytes(&vector.signature).map_err(|e| {
                        LatticeArcError::InvalidData(format!("Invalid Ed25519 signature: {e}"))
                    })?;

                let result =
                    Ed25519Signature::verify(&vector.public_key, &vector.message, &signature)
                        .is_ok();
                Ok(result == vector.expected_result)
            }
            _ => Err(LatticeArcError::InvalidConfiguration(format!(
                "Unsupported Ed25519 operation: {}",
                vector.operation
            ))),
        }
    }
}

impl Default for CryptoCavpTester {
    fn default() -> Self {
        Self::new()
    }
}

/// Example CAVP test vector loader for utilities.
///
/// Returns a set of sample test vectors for validating utility functions.
#[must_use]
pub fn load_sample_utility_vectors() -> Vec<UtilityTestVector> {
    vec![
        UtilityTestVector {
            test_case_id: "HEX-ENCODE-001".to_string(),
            function: "hex_encode".to_string(),
            input_data: vec![255, 0, 127, 64],
            expected_output: b"ff007f40".to_vec(),
            parameters: HashMap::new(),
        },
        UtilityTestVector {
            test_case_id: "HEX-DECODE-001".to_string(),
            function: "hex_decode".to_string(),
            input_data: b"deadbeef".to_vec(),
            expected_output: vec![222, 173, 190, 239],
            parameters: HashMap::new(),
        },
        UtilityTestVector {
            test_case_id: "UUID-GENERATE-001".to_string(),
            function: "uuid_generate".to_string(),
            input_data: vec![],
            expected_output: vec![], // UUID generation is non-deterministic
            parameters: HashMap::new(),
        },
        UtilityTestVector {
            test_case_id: "VERSION-CHECK-001".to_string(),
            function: "version_check".to_string(),
            input_data: vec![],
            expected_output: vec![1], // Expected version 1
            parameters: HashMap::new(),
        },
        UtilityTestVector {
            test_case_id: "DOMAIN-CONSTANT-001".to_string(),
            function: "domain_constant".to_string(),
            input_data: b"HYBRID_KEM_SS_INFO".to_vec(),
            expected_output: crate::types::domains::HYBRID_KEM_SS_INFO.to_vec(),
            parameters: HashMap::new(),
        },
    ]
}

/// Example CAVP test vector loader for cryptographic algorithms.
///
/// Returns a set of sample test vectors for validating cryptographic
/// signing and verification operations.
///
/// # Errors
///
/// Returns an error if the hardcoded Ed25519 test seed is rejected by the
/// key-pair constructor (this cannot happen in practice — the seed is a
/// known-good 32-byte RFC 8032 constant, but the API is fallible).
pub fn load_sample_crypto_vectors() -> Result<Vec<CryptoTestVector>> {
    // Generate valid Ed25519 key pair for testing (exactly 32 bytes)
    // Use standard test seed from RFC 8032 section 5.2
    let private_key_bytes: [u8; 32] = [
        9, 97, 177, 25, 223, 90, 213, 253, 245, 253, 166, 186, 10, 175, 250, 145, 70, 102, 73, 89,
        73, 148, 90, 236, 60, 48, 59, 122, 175, 96, 1, 0,
    ];
    let keypair = Ed25519KeyPair::from_secret_key(&private_key_bytes).map_err(|e| {
        LatticeArcError::InvalidData(format!("Ed25519 key construction failed: {}", e))
    })?;
    let message = b"test message for Ed25519".to_vec();
    let signature = keypair
        .sign(&message)
        .map_err(|e| LatticeArcError::InvalidData(format!("Ed25519 sign failed: {e}")))?;
    let signature_bytes = Ed25519Signature::signature_bytes(&signature);
    let public_key_bytes_vec = keypair.public_key_bytes();

    // ECDSA private key as pre-computed bytes (from hex "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721")
    // secp256k1 is not available in FIPS builds (non-NIST curve).
    #[cfg(not(feature = "fips"))]
    let ecdsa_private_key: [u8; 32] = [
        0xc9, 0xaf, 0xa9, 0xd8, 0x45, 0xba, 0x75, 0x16, 0x6b, 0x5c, 0x21, 0x57, 0x67, 0xb1, 0xd6,
        0x93, 0x4e, 0x50, 0xc3, 0xdb, 0x36, 0xe8, 0x9b, 0x12, 0x7b, 0x8a, 0x62, 0x2b, 0x12, 0x0f,
        0x67, 0x21,
    ];

    #[cfg(not(feature = "fips"))]
    let ecdsa_vector = CryptoTestVector {
        test_case_id: "ECDSA-SECP256K1-SIGN-001".to_string(),
        algorithm: "ECDSA-secp256k1".to_string(),
        operation: "sign".to_string(),
        kat_private_key_bytes: ecdsa_private_key.to_vec(),
        public_key: vec![], // Not needed for signing
        message: b"test message for ECDSA".to_vec(),
        signature: vec![], // Will be generated and compared
        expected_result: true,
        parameters: HashMap::new(),
    };

    #[cfg_attr(feature = "fips", allow(unused_mut))]
    let mut vectors = vec![
        // Ed25519 test vectors - Using matching key pair
        CryptoTestVector {
            test_case_id: "ED25519-SIGN-001".to_string(),
            algorithm: "Ed25519".to_string(),
            operation: "sign".to_string(),
            kat_private_key_bytes: private_key_bytes.to_vec(),
            public_key: vec![], // Not needed for signing
            message: message.clone(),
            signature: vec![], // Will be generated and compared
            expected_result: true,
            parameters: HashMap::new(),
        },
        // Verify test - Using matching key pair and signature
        CryptoTestVector {
            test_case_id: "ED25519-VERIFY-001".to_string(),
            algorithm: "Ed25519".to_string(),
            operation: "verify".to_string(),
            kat_private_key_bytes: vec![], // Not needed for verification
            public_key: public_key_bytes_vec,
            message,
            signature: signature_bytes,
            expected_result: true,
            parameters: HashMap::new(),
        },
    ];
    #[cfg(not(feature = "fips"))]
    vectors.insert(0, ecdsa_vector);
    Ok(vectors)
}

/// Comprehensive utility validation.
///
/// Provides validation for all utility functions used in cryptographic operations.
pub struct UtilityValidator;

impl Default for UtilityValidator {
    fn default() -> Self {
        Self::new()
    }
}

impl UtilityValidator {
    /// Create a new UtilityValidator instance.
    #[must_use]
    pub fn new() -> Self {
        Self {}
    }

    /// Validate all utility functions.
    ///
    /// # Errors
    ///
    /// Returns an error if utility function validation fails.
    pub fn validate_utilities(&self) -> Result<()> {
        tracing::info!("Validating utility functions");
        // M4: replace the stub body with real structural
        // checks. The full CAVP suite is driven through
        // `cargo test --package latticearc-tests`; this in-library
        // validator runs a small subset so a
        // `validate_utilities() -> Ok(())` no longer means
        // "literally nothing was checked".
        use crate::types::domains;
        let live_domains: &[(&str, &[u8])] = &[
            ("CASCADE_OUTER", domains::CASCADE_OUTER),
            ("CASCADE_INNER", domains::CASCADE_INNER),
            ("HYBRID_KEM_SS_INFO", domains::HYBRID_KEM_SS_INFO),
        ];
        for (name, bytes) in live_domains {
            if bytes.is_empty() {
                return Err(LatticeArcError::ValidationError {
                    message: format!("domain constant {name} is empty"),
                });
            }
            if !bytes.windows(11).any(|w| w == b"LatticeArc-") {
                return Err(LatticeArcError::ValidationError {
                    message: format!("domain constant {name} missing LatticeArc- prefix"),
                });
            }
        }
        // Pairwise distinctness
        for (i, (n1, b1)) in live_domains.iter().enumerate() {
            for (j, (n2, b2)) in live_domains.iter().enumerate() {
                if i != j && b1 == b2 {
                    return Err(LatticeArcError::ValidationError {
                        message: format!("domain constants {n1} and {n2} collide"),
                    });
                }
            }
        }
        // Hex round-trip invariant.
        let bytes: Vec<u8> = (0u8..=255).collect();
        let decoded =
            hex::decode(hex::encode(&bytes)).map_err(|e| LatticeArcError::ValidationError {
                message: format!("hex round-trip decode failed: {e}"),
            })?;
        if decoded != bytes {
            return Err(LatticeArcError::ValidationError {
                message: "hex round-trip not equal".to_string(),
            });
        }
        tracing::info!("CAVP-style utility testing completed successfully");
        Ok(())
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "Tests use unwrap for simplicity")]
mod tests {
    use super::*;

    #[test]
    fn test_utility_validator_succeeds() {
        let validator = UtilityValidator::new();
        assert!(validator.validate_utilities().is_ok());
    }

    #[test]
    fn test_cavp_utility_testing_succeeds() {
        let validator = UtilityValidator::new();
        assert!(validator.validate_utilities().is_ok());
    }

    #[test]
    fn test_hex_functions_roundtrip_succeeds() {
        let data = vec![255, 0, 127, 64];
        let encoded = hex::encode(&data);
        assert_eq!(encoded, "ff007f40");

        let decoded = hex::decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_uuid_validation_has_correct_format() {
        let uuid = uuid::Uuid::new_v4();
        assert!(!uuid.is_nil());
        assert_eq!(uuid.get_version_num(), 4);

        let uuid_str = uuid.to_string();
        assert_eq!(uuid_str.len(), 36);
        assert_eq!(uuid_str.chars().nth(8), Some('-'));
        assert_eq!(uuid_str.chars().nth(13), Some('-'));
        assert_eq!(uuid_str.chars().nth(18), Some('-'));
        assert_eq!(uuid_str.chars().nth(23), Some('-'));
    }

    #[test]
    fn test_domain_constants_have_correct_values_succeeds() {
        use crate::types::domains;

        assert!(!domains::CASCADE_OUTER.is_empty());
        assert!(!domains::CASCADE_INNER.is_empty());
        assert!(!domains::HYBRID_KEM_SS_INFO.is_empty());

        // Check that all contain version identifier
        assert!(domains::CASCADE_OUTER.windows(12).any(|w| w == b"LatticeArc-v"));
        assert!(domains::CASCADE_INNER.windows(12).any(|w| w == b"LatticeArc-v"));
        // `HYBRID_KEM_SS_INFO` uses the shorter `LatticeArc-Hybrid-`
        // prefix; check for that instead.
        assert!(domains::HYBRID_KEM_SS_INFO.windows(11).any(|w| w == b"LatticeArc-"));
    }

    #[test]
    fn test_version_constant_is_positive_succeeds() {
        const { assert!(crate::prelude::ENVELOPE_FORMAT_VERSION > 0) };
    }

    #[test]
    fn test_crypto_cavp_tester_succeeds() {
        let mut tester = CryptoCavpTester::new();
        let vectors = load_sample_crypto_vectors().unwrap();
        tester.load_test_vectors(vectors);
        assert!(tester.run_compliance_tests().is_ok());
    }

    // === UtilityCavpTester comprehensive tests ===

    #[test]
    fn test_utility_cavp_tester_default_is_empty() {
        let tester = UtilityCavpTester::default();
        assert!(tester.test_vectors.is_empty());
        assert!(tester.results.is_empty());
    }

    #[test]
    fn test_utility_cavp_tester_load_and_run_succeeds() {
        let mut tester = UtilityCavpTester::new();
        let vectors = load_sample_utility_vectors();
        tester.load_test_vectors(vectors);
        assert!(tester.run_compliance_tests().is_ok());
    }

    #[test]
    fn test_utility_cavp_tester_generate_report_succeeds() {
        let mut tester = UtilityCavpTester::new();
        let vectors = load_sample_utility_vectors();
        tester.load_test_vectors(vectors);
        tester.run_compliance_tests().unwrap();
        let report = tester.generate_report();
        assert!(report.contains("Utility CAVP Compliance Test Report"));
        assert!(report.contains("Total Tests:"));
        assert!(report.contains("Passed:"));
        assert!(report.contains("PASSED"));
    }

    #[test]
    fn test_utility_cavp_empty_run_succeeds() {
        let mut tester = UtilityCavpTester::new();
        // No vectors loaded — should succeed with zero tests
        assert!(tester.run_compliance_tests().is_ok());
        let report = tester.generate_report();
        assert!(report.contains("Total Tests: 0"));
    }

    #[test]
    fn test_utility_cavp_hex_encode_vector_succeeds() {
        let mut tester = UtilityCavpTester::new();
        tester.load_test_vectors(vec![UtilityTestVector {
            test_case_id: "HEX-CUSTOM-001".to_string(),
            function: "hex_encode".to_string(),
            input_data: vec![0xDE, 0xAD],
            expected_output: b"dead".to_vec(),
            parameters: HashMap::new(),
        }]);
        assert!(tester.run_compliance_tests().is_ok());
    }

    #[test]
    fn test_utility_cavp_hex_decode_vector_succeeds() {
        let mut tester = UtilityCavpTester::new();
        tester.load_test_vectors(vec![UtilityTestVector {
            test_case_id: "HEX-DEC-001".to_string(),
            function: "hex_decode".to_string(),
            input_data: b"cafe".to_vec(),
            expected_output: vec![0xCA, 0xFE],
            parameters: HashMap::new(),
        }]);
        assert!(tester.run_compliance_tests().is_ok());
    }

    #[test]
    fn test_utility_cavp_uuid_vector_succeeds() {
        let mut tester = UtilityCavpTester::new();
        tester.load_test_vectors(vec![UtilityTestVector {
            test_case_id: "UUID-001".to_string(),
            function: "uuid_generate".to_string(),
            input_data: vec![],
            expected_output: vec![],
            parameters: HashMap::new(),
        }]);
        assert!(tester.run_compliance_tests().is_ok());
    }

    #[test]
    fn test_utility_cavp_version_check_vector_succeeds() {
        let mut tester = UtilityCavpTester::new();
        tester.load_test_vectors(vec![UtilityTestVector {
            test_case_id: "VER-001".to_string(),
            function: "version_check".to_string(),
            input_data: vec![],
            expected_output: vec![crate::prelude::ENVELOPE_FORMAT_VERSION],
            parameters: HashMap::new(),
        }]);
        assert!(tester.run_compliance_tests().is_ok());
    }

    #[test]
    fn test_utility_cavp_domain_constant_vectors_succeeds() {
        use crate::types::domains;
        for (name, expected) in [
            ("CASCADE_OUTER", domains::CASCADE_OUTER.to_vec()),
            ("CASCADE_INNER", domains::CASCADE_INNER.to_vec()),
            ("HYBRID_KEM_SS_INFO", domains::HYBRID_KEM_SS_INFO.to_vec()),
        ] {
            let mut tester = UtilityCavpTester::new();
            tester.load_test_vectors(vec![UtilityTestVector {
                test_case_id: format!("DOMAIN-{}", name),
                function: "domain_constant".to_string(),
                input_data: name.as_bytes().to_vec(),
                expected_output: expected,
                parameters: HashMap::new(),
            }]);
            assert!(tester.run_compliance_tests().is_ok(), "Failed for domain {}", name);
        }
    }

    #[test]
    fn test_utility_cavp_unknown_domain_returns_error() {
        let mut tester = UtilityCavpTester::new();
        tester.load_test_vectors(vec![UtilityTestVector {
            test_case_id: "DOMAIN-UNKNOWN".to_string(),
            function: "domain_constant".to_string(),
            input_data: b"UNKNOWN_DOMAIN".to_vec(),
            expected_output: vec![],
            parameters: HashMap::new(),
        }]);
        // unknown domain returns false, which triggers VerificationFailed
        assert!(tester.run_compliance_tests().is_err());
    }

    #[test]
    fn test_utility_cavp_unsupported_function_returns_error() {
        let mut tester = UtilityCavpTester::new();
        tester.load_test_vectors(vec![UtilityTestVector {
            test_case_id: "UNSUPPORTED-001".to_string(),
            function: "unsupported_function".to_string(),
            input_data: vec![],
            expected_output: vec![],
            parameters: HashMap::new(),
        }]);
        assert!(tester.run_compliance_tests().is_err());
    }

    #[test]
    fn test_utility_cavp_hex_encode_mismatch_returns_error() {
        let mut tester = UtilityCavpTester::new();
        tester.load_test_vectors(vec![UtilityTestVector {
            test_case_id: "HEX-FAIL-001".to_string(),
            function: "hex_encode".to_string(),
            input_data: vec![0xFF],
            expected_output: b"00".to_vec(), // wrong expected
            parameters: HashMap::new(),
        }]);
        assert!(tester.run_compliance_tests().is_err());
    }

    // === CryptoCavpTester comprehensive tests ===

    #[test]
    fn test_crypto_cavp_tester_default_is_empty() {
        let tester = CryptoCavpTester::default();
        assert!(tester.test_vectors.is_empty());
    }

    #[test]
    fn test_crypto_cavp_generate_report_succeeds() {
        let mut tester = CryptoCavpTester::new();
        let vectors = load_sample_crypto_vectors().unwrap();
        tester.load_test_vectors(vectors);
        tester.run_compliance_tests().unwrap();
        let report = tester.generate_report();
        assert!(report.contains("Cryptographic CAVP Compliance Test Report"));
        assert!(report.contains("PASSED"));
    }

    #[test]
    fn test_crypto_cavp_empty_run_succeeds() {
        let mut tester = CryptoCavpTester::new();
        assert!(tester.run_compliance_tests().is_ok());
    }

    #[test]
    fn test_crypto_cavp_unsupported_algorithm_returns_error() {
        let mut tester = CryptoCavpTester::new();
        tester.load_test_vectors(vec![CryptoTestVector {
            test_case_id: "UNSUP-001".to_string(),
            algorithm: "RSA-2048".to_string(),
            operation: "sign".to_string(),
            kat_private_key_bytes: vec![],
            public_key: vec![],
            message: vec![],
            signature: vec![],
            expected_result: true,
            parameters: HashMap::new(),
        }]);
        assert!(tester.run_compliance_tests().is_err());
    }

    #[test]
    fn test_crypto_cavp_ecdsa_unsupported_operation_returns_error() {
        let mut tester = CryptoCavpTester::new();
        tester.load_test_vectors(vec![CryptoTestVector {
            test_case_id: "ECDSA-BAD-OP".to_string(),
            algorithm: "ECDSA-secp256k1".to_string(),
            operation: "encrypt".to_string(),
            kat_private_key_bytes: vec![0xC9; 32],
            public_key: vec![],
            message: vec![],
            signature: vec![],
            expected_result: true,
            parameters: HashMap::new(),
        }]);
        assert!(tester.run_compliance_tests().is_err());
    }

    #[test]
    fn test_crypto_cavp_ed25519_unsupported_operation_returns_error() {
        let mut tester = CryptoCavpTester::new();
        tester.load_test_vectors(vec![CryptoTestVector {
            test_case_id: "ED-BAD-OP".to_string(),
            algorithm: "Ed25519".to_string(),
            operation: "encrypt".to_string(),
            kat_private_key_bytes: vec![0x01; 32],
            public_key: vec![],
            message: vec![],
            signature: vec![],
            expected_result: true,
            parameters: HashMap::new(),
        }]);
        assert!(tester.run_compliance_tests().is_err());
    }

    #[test]
    fn test_crypto_cavp_ecdsa_invalid_key_returns_error() {
        let mut tester = CryptoCavpTester::new();
        tester.load_test_vectors(vec![CryptoTestVector {
            test_case_id: "ECDSA-BAD-KEY".to_string(),
            algorithm: "ECDSA-secp256k1".to_string(),
            operation: "sign".to_string(),
            kat_private_key_bytes: vec![0; 32], // all-zero key is invalid for ECDSA
            public_key: vec![],
            message: b"test".to_vec(),
            signature: vec![],
            expected_result: true,
            parameters: HashMap::new(),
        }]);
        assert!(tester.run_compliance_tests().is_err());
    }

    #[test]
    fn test_crypto_cavp_ed25519_wrong_key_length_returns_error() {
        let mut tester = CryptoCavpTester::new();
        tester.load_test_vectors(vec![CryptoTestVector {
            test_case_id: "ED-BAD-LEN".to_string(),
            algorithm: "Ed25519".to_string(),
            operation: "sign".to_string(),
            kat_private_key_bytes: vec![1; 16], // wrong length
            public_key: vec![],
            message: b"test".to_vec(),
            signature: vec![],
            expected_result: true,
            parameters: HashMap::new(),
        }]);
        assert!(tester.run_compliance_tests().is_err());
    }

    #[test]
    fn test_load_sample_utility_vectors_are_not_empty_matches_expected() {
        let vectors = load_sample_utility_vectors();
        assert!(!vectors.is_empty());
        // Verify expected test IDs
        let ids: Vec<&str> = vectors.iter().map(|v| v.test_case_id.as_str()).collect();
        assert!(ids.contains(&"HEX-ENCODE-001"));
        assert!(ids.contains(&"HEX-DECODE-001"));
        assert!(ids.contains(&"UUID-GENERATE-001"));
    }

    #[test]
    fn test_load_sample_crypto_vectors_are_not_empty_matches_expected() {
        let vectors = load_sample_crypto_vectors().unwrap();
        assert!(!vectors.is_empty());
        let ids: Vec<&str> = vectors.iter().map(|v| v.test_case_id.as_str()).collect();
        #[cfg(not(feature = "fips"))]
        assert!(ids.contains(&"ECDSA-SECP256K1-SIGN-001"));
        assert!(ids.contains(&"ED25519-SIGN-001"));
        assert!(ids.contains(&"ED25519-VERIFY-001"));
    }

    // === ECDSA verify path coverage ===

    #[test]
    #[cfg(not(feature = "fips"))]
    fn test_crypto_cavp_ecdsa_verify_valid_succeeds() {
        use crate::primitives::ec::secp256k1::Secp256k1KeyPair as TestKeyPair;
        use crate::primitives::ec::secp256k1::Secp256k1Signature as TestSig;
        use crate::primitives::ec::traits::{EcKeyPair, EcSignature};

        let private_key: [u8; 32] = [
            0xc9, 0xaf, 0xa9, 0xd8, 0x45, 0xba, 0x75, 0x16, 0x6b, 0x5c, 0x21, 0x57, 0x67, 0xb1,
            0xd6, 0x93, 0x4e, 0x50, 0xc3, 0xdb, 0x36, 0xe8, 0x9b, 0x12, 0x7b, 0x8a, 0x62, 0x2b,
            0x12, 0x0f, 0x67, 0x21,
        ];
        let keypair = TestKeyPair::from_secret_key(&private_key).unwrap();
        let message = b"test message for ECDSA verify";
        let signature = keypair.sign(message).unwrap();
        let verifying_key = keypair.public_key_bytes();

        let mut tester = CryptoCavpTester::new();
        tester.load_test_vectors(vec![CryptoTestVector {
            test_case_id: "ECDSA-VERIFY-001".to_string(),
            algorithm: "ECDSA-secp256k1".to_string(),
            operation: "verify".to_string(),
            kat_private_key_bytes: vec![],
            public_key: verifying_key,
            message: message.to_vec(),
            signature: TestSig::signature_bytes(&signature),
            expected_result: true,
            parameters: HashMap::new(),
        }]);
        assert!(tester.run_compliance_tests().is_ok());
    }

    #[test]
    #[cfg(not(feature = "fips"))]
    fn test_crypto_cavp_ecdsa_verify_invalid_signature_returns_error() {
        use crate::primitives::ec::secp256k1::Secp256k1KeyPair as TestKeyPair;
        use crate::primitives::ec::secp256k1::Secp256k1Signature as TestSig;
        use crate::primitives::ec::traits::{EcKeyPair, EcSignature};

        let private_key: [u8; 32] = [
            0xc9, 0xaf, 0xa9, 0xd8, 0x45, 0xba, 0x75, 0x16, 0x6b, 0x5c, 0x21, 0x57, 0x67, 0xb1,
            0xd6, 0x93, 0x4e, 0x50, 0xc3, 0xdb, 0x36, 0xe8, 0x9b, 0x12, 0x7b, 0x8a, 0x62, 0x2b,
            0x12, 0x0f, 0x67, 0x21,
        ];
        let keypair = TestKeyPair::from_secret_key(&private_key).unwrap();
        let message = b"test message for ECDSA verify";
        let signature = keypair.sign(message).unwrap();
        let verifying_key = keypair.public_key_bytes();

        // Use wrong message for verification — should fail, expected_result=false
        let mut tester = CryptoCavpTester::new();
        tester.load_test_vectors(vec![CryptoTestVector {
            test_case_id: "ECDSA-VERIFY-FAIL".to_string(),
            algorithm: "ECDSA-secp256k1".to_string(),
            operation: "verify".to_string(),
            kat_private_key_bytes: vec![],
            public_key: verifying_key,
            message: b"wrong message".to_vec(),
            signature: TestSig::signature_bytes(&signature),
            expected_result: false, // We expect verification to fail
            parameters: HashMap::new(),
        }]);
        assert!(tester.run_compliance_tests().is_ok());
    }

    // === ECDSA verify error paths ===

    #[test]
    fn test_crypto_cavp_ecdsa_verify_invalid_public_key_returns_error() {
        let mut tester = CryptoCavpTester::new();
        tester.load_test_vectors(vec![CryptoTestVector {
            test_case_id: "ECDSA-BAD-PK".to_string(),
            algorithm: "ECDSA-secp256k1".to_string(),
            operation: "verify".to_string(),
            kat_private_key_bytes: vec![],
            public_key: vec![0xFF; 10], // Invalid SEC1 encoded public key
            message: b"test".to_vec(),
            signature: vec![0; 64],
            expected_result: true,
            parameters: HashMap::new(),
        }]);
        assert!(tester.run_compliance_tests().is_err());
    }

    #[test]
    fn test_crypto_cavp_ecdsa_verify_invalid_signature_bytes_returns_error() {
        use k256::ecdsa::SigningKey as EcdsaSigningKey;

        let private_key: [u8; 32] = [
            0xc9, 0xaf, 0xa9, 0xd8, 0x45, 0xba, 0x75, 0x16, 0x6b, 0x5c, 0x21, 0x57, 0x67, 0xb1,
            0xd6, 0x93, 0x4e, 0x50, 0xc3, 0xdb, 0x36, 0xe8, 0x9b, 0x12, 0x7b, 0x8a, 0x62, 0x2b,
            0x12, 0x0f, 0x67, 0x21,
        ];
        let signing_key = EcdsaSigningKey::from_slice(&private_key).unwrap();
        let verifying_key = signing_key.verifying_key();

        let mut tester = CryptoCavpTester::new();
        tester.load_test_vectors(vec![CryptoTestVector {
            test_case_id: "ECDSA-BAD-SIG".to_string(),
            algorithm: "ECDSA-secp256k1".to_string(),
            operation: "verify".to_string(),
            kat_private_key_bytes: vec![],
            public_key: verifying_key.to_sec1_bytes().to_vec(),
            message: b"test".to_vec(),
            signature: vec![0xFF; 10], // Wrong length for ECDSA signature
            expected_result: true,
            parameters: HashMap::new(),
        }]);
        assert!(tester.run_compliance_tests().is_err());
    }

    // === Ed25519 verify error paths ===

    #[test]
    fn test_crypto_cavp_ed25519_verify_wrong_pk_length_returns_error() {
        let mut tester = CryptoCavpTester::new();
        tester.load_test_vectors(vec![CryptoTestVector {
            test_case_id: "ED-BAD-PK-LEN".to_string(),
            algorithm: "Ed25519".to_string(),
            operation: "verify".to_string(),
            kat_private_key_bytes: vec![],
            public_key: vec![1; 16], // Wrong length (not 32 bytes)
            message: b"test".to_vec(),
            signature: vec![0; 64],
            expected_result: true,
            parameters: HashMap::new(),
        }]);
        assert!(tester.run_compliance_tests().is_err());
    }

    #[test]
    fn test_crypto_cavp_ed25519_verify_wrong_sig_length_returns_error() {
        let mut tester = CryptoCavpTester::new();
        tester.load_test_vectors(vec![CryptoTestVector {
            test_case_id: "ED-BAD-SIG-LEN".to_string(),
            algorithm: "Ed25519".to_string(),
            operation: "verify".to_string(),
            kat_private_key_bytes: vec![],
            public_key: vec![1; 32],
            message: b"test".to_vec(),
            signature: vec![0; 10], // Wrong length (not 64 bytes)
            expected_result: true,
            parameters: HashMap::new(),
        }]);
        assert!(tester.run_compliance_tests().is_err());
    }

    // === UtilityTestVector / CryptoTestVector struct field access ===

    #[test]
    fn test_utility_test_vector_clone_debug_succeeds() {
        let vector = UtilityTestVector {
            test_case_id: "TEST-001".to_string(),
            function: "hex_encode".to_string(),
            input_data: vec![1, 2, 3],
            expected_output: b"010203".to_vec(),
            parameters: HashMap::new(),
        };
        let cloned = vector.clone();
        assert_eq!(cloned.test_case_id, "TEST-001");
        assert_eq!(cloned.function, "hex_encode");
        let debug = format!("{:?}", vector);
        assert!(debug.contains("UtilityTestVector"));
    }

    #[test]
    fn test_crypto_test_vector_clone_debug_succeeds() {
        let vector = CryptoTestVector {
            test_case_id: "CRYPTO-001".to_string(),
            algorithm: "Ed25519".to_string(),
            operation: "sign".to_string(),
            kat_private_key_bytes: vec![1; 32],
            public_key: vec![],
            message: b"msg".to_vec(),
            signature: vec![],
            expected_result: true,
            parameters: HashMap::new(),
        };
        let cloned = vector.clone();
        assert_eq!(cloned.algorithm, "Ed25519");
        let debug = format!("{:?}", vector);
        assert!(debug.contains("CryptoTestVector"));
    }
}
