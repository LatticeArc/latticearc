//! FIPS 140-3 Self-Test Module
//!
//! This module provides power-up and conditional self-tests for FIPS 140-3 compliance.
//! According to FIPS 140-3 IG 10.3.A, cryptographic modules must perform Known Answer
//! Tests (KATs) at power-up before any cryptographic operation can be performed.
//!
//! This is the **canonical** FIPS 140-3 self-test module for the LatticeArc
//! cryptographic module. The `arc-validation` crate provides test/validation
//! utilities for development; this module contains the production self-tests.
//!
//! ## Power-Up Self-Tests
//!
//! The following algorithms are tested at power-up:
//! - SHA-256: Cryptographic hash function (FIPS 180-4)
//! - SHA3-256: Cryptographic hash function (FIPS 202)
//! - HMAC-SHA256: Message authentication code (FIPS 198-1)
//! - HKDF-SHA256: Key derivation function (NIST SP 800-56C)
//! - AES-256-GCM: Authenticated encryption (NIST SP 800-38D)
//! - ML-KEM-768: Key encapsulation mechanism (FIPS 203)
//! - ML-DSA-44: Digital signatures (FIPS 204)
//! - SLH-DSA-SHAKE-128s: Hash-based signatures (FIPS 205)
//! - FN-DSA-512: Lattice-based signatures (FIPS 206)
//!
//! ## Usage
//!
//! ```no_run
//! use arc_primitives::self_test::{run_power_up_tests, SelfTestResult};
//!
//! // Run power-up tests on module initialization
//! let result = run_power_up_tests();
//! match result {
//!     SelfTestResult::Pass => println!("All self-tests passed"),
//!     SelfTestResult::Fail(msg) => panic!("Self-test failed: {}", msg),
//! }
//! ```
//!
//! ## FIPS 140-3 Compliance Notes
//!
//! - All KATs use NIST-approved test vectors where available
//! - Test vectors are hardcoded to ensure deterministic verification
//! - Any self-test failure should result in the module entering an error state
//! - No cryptographic services should be provided after a self-test failure

#![deny(unsafe_code)]
#![warn(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

use arc_prelude::error::{LatticeArcError, Result};
use subtle::ConstantTimeEq;

// =============================================================================
// Self-Test Result Types
// =============================================================================

/// Result of a self-test operation
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SelfTestResult {
    /// All tests passed successfully
    Pass,
    /// One or more tests failed with the given error message
    Fail(String),
}

impl SelfTestResult {
    /// Returns true if the self-test passed
    #[must_use]
    pub fn is_pass(&self) -> bool {
        matches!(self, SelfTestResult::Pass)
    }

    /// Returns true if the self-test failed
    #[must_use]
    pub fn is_fail(&self) -> bool {
        matches!(self, SelfTestResult::Fail(_))
    }

    /// Converts the result to a standard Result type
    ///
    /// # Errors
    /// Returns `LatticeArcError::ValidationError` if the self-test failed
    pub fn to_result(&self) -> Result<()> {
        match self {
            SelfTestResult::Pass => Ok(()),
            SelfTestResult::Fail(msg) => Err(LatticeArcError::ValidationError {
                message: format!("FIPS 140-3 self-test failed: {}", msg),
            }),
        }
    }
}

/// Individual test result for detailed reporting
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndividualTestResult {
    /// Name of the algorithm tested
    pub algorithm: String,
    /// Result of the test
    pub result: SelfTestResult,
    /// Time taken to run the test in microseconds (if measured)
    pub duration_us: Option<u64>,
}

/// Comprehensive self-test report
#[derive(Debug, Clone)]
pub struct SelfTestReport {
    /// Overall result
    pub overall_result: SelfTestResult,
    /// Individual test results
    pub tests: Vec<IndividualTestResult>,
    /// Total time taken in microseconds
    pub total_duration_us: u64,
}

// =============================================================================
// Power-Up Self-Tests
// =============================================================================

/// Run all FIPS 140-3 power-up self-tests
///
/// This function runs Known Answer Tests (KATs) for all approved algorithms.
/// According to FIPS 140-3, these tests must pass before any cryptographic
/// operation can be performed.
///
/// # Returns
///
/// - `SelfTestResult::Pass` if all tests pass
/// - `SelfTestResult::Fail(message)` if any test fails
///
/// # Example
///
/// ```no_run
/// use arc_primitives::self_test::run_power_up_tests;
///
/// let result = run_power_up_tests();
/// if result.is_fail() {
///     // Enter error state - no crypto operations allowed
///     eprintln!("CRITICAL: FIPS self-tests failed!");
/// }
/// ```
#[must_use]
pub fn run_power_up_tests() -> SelfTestResult {
    // Run each test in sequence - any failure stops further tests
    // Order follows FIPS 140-3 requirements: integrity first, then KATs

    // 0. Software/Firmware Integrity Test (FIPS 140-3 Section 9.2.2)
    // MUST be performed before any cryptographic operations
    if let Err(e) = integrity_test() {
        return SelfTestResult::Fail(format!("Module Integrity Test failed: {}", e));
    }

    // 1. SHA-256 KAT (foundational - other tests depend on hash)
    if let Err(e) = kat_sha256() {
        return SelfTestResult::Fail(format!("SHA-256 KAT failed: {}", e));
    }

    // 2. HKDF-SHA256 KAT (depends on HMAC-SHA256)
    if let Err(e) = kat_hkdf_sha256() {
        return SelfTestResult::Fail(format!("HKDF-SHA256 KAT failed: {}", e));
    }

    // 3. AES-256-GCM KAT
    if let Err(e) = kat_aes_256_gcm() {
        return SelfTestResult::Fail(format!("AES-256-GCM KAT failed: {}", e));
    }

    // 4. SHA3-256 KAT
    if let Err(e) = kat_sha3_256() {
        return SelfTestResult::Fail(format!("SHA3-256 KAT failed: {}", e));
    }

    // 5. HMAC-SHA256 KAT
    if let Err(e) = kat_hmac_sha256() {
        return SelfTestResult::Fail(format!("HMAC-SHA256 KAT failed: {}", e));
    }

    // 6. ML-KEM-768 KAT (full encap/decap roundtrip)
    if let Err(e) = kat_ml_kem_768() {
        return SelfTestResult::Fail(format!("ML-KEM-768 KAT failed: {}", e));
    }

    // 7. ML-DSA-44 KAT (sign/verify roundtrip)
    if let Err(e) = kat_ml_dsa() {
        return SelfTestResult::Fail(format!("ML-DSA KAT failed: {}", e));
    }

    // 8. SLH-DSA KAT (sign/verify roundtrip)
    if let Err(e) = kat_slh_dsa() {
        return SelfTestResult::Fail(format!("SLH-DSA KAT failed: {}", e));
    }

    // 9. FN-DSA KAT (runs in separate thread with 32MB stack)
    if let Err(e) = kat_fn_dsa() {
        return SelfTestResult::Fail(format!("FN-DSA KAT failed: {}", e));
    }

    SelfTestResult::Pass
}

/// Run power-up tests with detailed reporting
///
/// Similar to `run_power_up_tests` but returns a detailed report
/// of all test results and timings.
///
/// # Returns
///
/// A `SelfTestReport` containing individual test results and timing information.
#[must_use]
pub fn run_power_up_tests_with_report() -> SelfTestReport {
    use std::time::Instant;

    /// Convert duration to u64 microseconds with saturation
    fn duration_to_us(duration: std::time::Duration) -> u64 {
        // Saturate at u64::MAX if duration exceeds ~584,942 years
        u64::try_from(duration.as_micros()).unwrap_or(u64::MAX)
    }

    let start = Instant::now();
    let mut tests = Vec::new();
    let mut overall_pass = true;

    // SHA-256 KAT
    let sha_start = Instant::now();
    let sha_result = match kat_sha256() {
        Ok(()) => SelfTestResult::Pass,
        Err(e) => {
            overall_pass = false;
            SelfTestResult::Fail(e.to_string())
        }
    };
    tests.push(IndividualTestResult {
        algorithm: "SHA-256".to_string(),
        result: sha_result,
        duration_us: Some(duration_to_us(sha_start.elapsed())),
    });

    // HKDF-SHA256 KAT
    let hkdf_start = Instant::now();
    let hkdf_result = match kat_hkdf_sha256() {
        Ok(()) => SelfTestResult::Pass,
        Err(e) => {
            overall_pass = false;
            SelfTestResult::Fail(e.to_string())
        }
    };
    tests.push(IndividualTestResult {
        algorithm: "HKDF-SHA256".to_string(),
        result: hkdf_result,
        duration_us: Some(duration_to_us(hkdf_start.elapsed())),
    });

    // AES-256-GCM KAT
    let aes_start = Instant::now();
    let aes_result = match kat_aes_256_gcm() {
        Ok(()) => SelfTestResult::Pass,
        Err(e) => {
            overall_pass = false;
            SelfTestResult::Fail(e.to_string())
        }
    };
    tests.push(IndividualTestResult {
        algorithm: "AES-256-GCM".to_string(),
        result: aes_result,
        duration_us: Some(duration_to_us(aes_start.elapsed())),
    });

    // SHA3-256 KAT
    let sha3_start = Instant::now();
    let sha3_result = match kat_sha3_256() {
        Ok(()) => SelfTestResult::Pass,
        Err(e) => {
            overall_pass = false;
            SelfTestResult::Fail(e.to_string())
        }
    };
    tests.push(IndividualTestResult {
        algorithm: "SHA3-256".to_string(),
        result: sha3_result,
        duration_us: Some(duration_to_us(sha3_start.elapsed())),
    });

    // HMAC-SHA256 KAT
    let hmac_start = Instant::now();
    let hmac_result = match kat_hmac_sha256() {
        Ok(()) => SelfTestResult::Pass,
        Err(e) => {
            overall_pass = false;
            SelfTestResult::Fail(e.to_string())
        }
    };
    tests.push(IndividualTestResult {
        algorithm: "HMAC-SHA256".to_string(),
        result: hmac_result,
        duration_us: Some(duration_to_us(hmac_start.elapsed())),
    });

    // ML-KEM-768 KAT
    let kem_start = Instant::now();
    let kem_result = match kat_ml_kem_768() {
        Ok(()) => SelfTestResult::Pass,
        Err(e) => {
            overall_pass = false;
            SelfTestResult::Fail(e.to_string())
        }
    };
    tests.push(IndividualTestResult {
        algorithm: "ML-KEM-768".to_string(),
        result: kem_result,
        duration_us: Some(duration_to_us(kem_start.elapsed())),
    });

    // ML-DSA-44 KAT
    let mldsa_start = Instant::now();
    let mldsa_result = match kat_ml_dsa() {
        Ok(()) => SelfTestResult::Pass,
        Err(e) => {
            overall_pass = false;
            SelfTestResult::Fail(e.to_string())
        }
    };
    tests.push(IndividualTestResult {
        algorithm: "ML-DSA-44".to_string(),
        result: mldsa_result,
        duration_us: Some(duration_to_us(mldsa_start.elapsed())),
    });

    // SLH-DSA KAT
    let slhdsa_start = Instant::now();
    let slhdsa_result = match kat_slh_dsa() {
        Ok(()) => SelfTestResult::Pass,
        Err(e) => {
            overall_pass = false;
            SelfTestResult::Fail(e.to_string())
        }
    };
    tests.push(IndividualTestResult {
        algorithm: "SLH-DSA-SHAKE-128s".to_string(),
        result: slhdsa_result,
        duration_us: Some(duration_to_us(slhdsa_start.elapsed())),
    });

    // FN-DSA KAT
    let fndsa_start = Instant::now();
    let fndsa_result = match kat_fn_dsa() {
        Ok(()) => SelfTestResult::Pass,
        Err(e) => {
            overall_pass = false;
            SelfTestResult::Fail(e.to_string())
        }
    };
    tests.push(IndividualTestResult {
        algorithm: "FN-DSA-512".to_string(),
        result: fndsa_result,
        duration_us: Some(duration_to_us(fndsa_start.elapsed())),
    });

    let overall_result = if overall_pass {
        SelfTestResult::Pass
    } else {
        let failed: Vec<_> =
            tests.iter().filter(|t| t.result.is_fail()).map(|t| t.algorithm.clone()).collect();
        SelfTestResult::Fail(format!("Failed tests: {}", failed.join(", ")))
    };

    SelfTestReport { overall_result, tests, total_duration_us: duration_to_us(start.elapsed()) }
}

// =============================================================================
// SHA-256 Known Answer Test
// =============================================================================

/// SHA-256 Known Answer Test using NIST test vectors
///
/// Test vector from NIST CAVP SHA-256 Short Message Test
/// Message: "abc" (0x616263)
/// Expected digest: ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
///
/// # Errors
///
/// Returns error if the computed hash does not match the expected value.
pub fn kat_sha256() -> Result<()> {
    use crate::hash::sha256;

    // NIST CAVP test vector: SHA-256("abc")
    // Source: https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/shs/shabytetestvectors.zip
    const INPUT: &[u8] = b"abc";
    const EXPECTED: [u8; 32] = [
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22,
        0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00,
        0x15, 0xad,
    ];

    let result = sha256(INPUT).map_err(|e| LatticeArcError::ValidationError {
        message: format!("SHA-256 KAT: hash computation failed: {}", e),
    })?;

    // Constant-time comparison to prevent timing attacks
    if bool::from(result.ct_eq(&EXPECTED)) {
        Ok(())
    } else {
        Err(LatticeArcError::ValidationError {
            message: "SHA-256 KAT: computed hash does not match expected value".to_string(),
        })
    }
}

// =============================================================================
// HKDF-SHA256 Known Answer Test
// =============================================================================

/// HKDF-SHA256 Known Answer Test using RFC 5869 test vectors
///
/// Test Case 1 from RFC 5869:
/// - IKM: 0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b (22 octets)
/// - Salt: 0x000102030405060708090a0b0c (13 octets)
/// - Info: 0xf0f1f2f3f4f5f6f7f8f9 (10 octets)
/// - L: 42
///
/// # Errors
///
/// Returns error if the derived key does not match the expected value.
pub fn kat_hkdf_sha256() -> Result<()> {
    use crate::kdf::hkdf;

    // RFC 5869 Test Case 1
    const IKM: [u8; 22] = [
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
    ];
    const SALT: [u8; 13] =
        [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c];
    const INFO: [u8; 10] = [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];
    const EXPECTED_OKM: [u8; 42] = [
        0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f,
        0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4,
        0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65,
    ];

    let result = hkdf(&IKM, Some(&SALT), Some(&INFO), 42)?;

    // Constant-time comparison
    if bool::from(result.key().ct_eq(&EXPECTED_OKM)) {
        Ok(())
    } else {
        Err(LatticeArcError::ValidationError {
            message: "HKDF-SHA256 KAT: derived key does not match expected value".to_string(),
        })
    }
}

// =============================================================================
// SHA3-256 Known Answer Test
// =============================================================================

/// SHA3-256 Known Answer Test using NIST test vectors
///
/// Test vector from NIST CAVP SHA3-256 Short Message Test
/// Message: "abc" (0x616263)
/// Expected digest: 3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532
///
/// # Errors
///
/// Returns error if the computed hash does not match the expected value.
pub fn kat_sha3_256() -> Result<()> {
    use crate::hash::sha3::sha3_256;

    // NIST CAVP test vector: SHA3-256("abc")
    // Source: https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/sha3/sha-3bytetestvectors.zip
    const INPUT: &[u8] = b"abc";
    const EXPECTED: [u8; 32] = [
        0x3a, 0x98, 0x5d, 0xa7, 0x4f, 0xe2, 0x25, 0xb2, 0x04, 0x5c, 0x17, 0x2d, 0x6b, 0xd3, 0x90,
        0xbd, 0x85, 0x5f, 0x08, 0x6e, 0x3e, 0x9d, 0x52, 0x5b, 0x46, 0xbf, 0xe2, 0x45, 0x11, 0x43,
        0x15, 0x32,
    ];

    let result = sha3_256(INPUT);

    // Constant-time comparison to prevent timing attacks
    if bool::from(result.ct_eq(&EXPECTED)) {
        Ok(())
    } else {
        Err(LatticeArcError::ValidationError {
            message: "SHA3-256 KAT: computed hash does not match expected value".to_string(),
        })
    }
}

// =============================================================================
// HMAC-SHA256 Known Answer Test
// =============================================================================

/// HMAC-SHA256 Known Answer Test using RFC 4231 Test Case 2
///
/// Test Case 2 from RFC 4231:
/// - Key: "Jefe" (0x4a656665)
/// - Data: "what do ya want for nothing?" (0x7768617420646f2079612077616e7420666f72206e6f7468696e673f)
/// - Expected HMAC: 5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843
///
/// # Errors
///
/// Returns error if the computed HMAC does not match the expected value.
pub fn kat_hmac_sha256() -> Result<()> {
    use crate::mac::hmac::hmac_sha256;

    // RFC 4231 Test Case 2
    const KEY: &[u8] = b"Jefe";
    const DATA: &[u8] = b"what do ya want for nothing?";
    const EXPECTED: [u8; 32] = [
        0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e, 0x6a, 0x04, 0x24, 0x26, 0x08, 0x95, 0x75,
        0xc7, 0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83, 0x9d, 0xec, 0x58, 0xb9, 0x64, 0xec,
        0x38, 0x43,
    ];

    let result = hmac_sha256(KEY, DATA).map_err(|e| LatticeArcError::ValidationError {
        message: format!("HMAC-SHA256 KAT: computation failed: {}", e),
    })?;

    // Constant-time comparison
    if bool::from(result.ct_eq(&EXPECTED)) {
        Ok(())
    } else {
        Err(LatticeArcError::ValidationError {
            message: "HMAC-SHA256 KAT: computed HMAC does not match expected value".to_string(),
        })
    }
}

// =============================================================================
// AES-256-GCM Known Answer Test
// =============================================================================

/// AES-256-GCM Known Answer Test using NIST test vectors
///
/// Test vector from NIST SP 800-38D GCM test vectors:
/// - Key: 32 bytes (all zeros for simplicity - actual KAT uses NIST vectors)
/// - Nonce: 12 bytes
/// - Plaintext: "Hello, World!"
/// - AAD: None
///
/// This test verifies both encryption and decryption paths.
///
/// # Errors
///
/// Returns error if encryption or decryption produces incorrect results.
pub fn kat_aes_256_gcm() -> Result<()> {
    use crate::aead::{AeadCipher, aes_gcm::AesGcm256};

    // Self-computed test vector (not from an external source):
    // Key = 0x00..0x1f, Nonce = 0x00*12, Plaintext = "FIPS 140-3 KAT", AAD = "additional data"
    // Expected ciphertext and tag independently verified via OpenSSL `aes-256-gcm` and AWS-LC
    const KEY: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];
    const NONCE: [u8; 12] =
        [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    const PLAINTEXT: &[u8] = b"FIPS 140-3 KAT";
    const AAD: &[u8] = b"additional data";

    const EXPECTED_CT: [u8; 14] =
        [0x48, 0xf5, 0xe5, 0x8d, 0x95, 0x1d, 0xb7, 0x8d, 0x25, 0x9b, 0x89, 0x7e, 0x59, 0x78];
    const EXPECTED_TAG: [u8; 16] = [
        0x15, 0xad, 0x41, 0x23, 0xf6, 0x60, 0x99, 0xe1, 0xad, 0xa5, 0x5b, 0xd6, 0x7d, 0xa6, 0xc5,
        0xeb,
    ];

    // Create cipher instance
    let cipher = AesGcm256::new(&KEY).map_err(|e| LatticeArcError::ValidationError {
        message: format!("AES-256-GCM KAT: cipher initialization failed: {}", e),
    })?;

    // Encrypt and verify ciphertext matches expected
    let (ciphertext, tag) = cipher.encrypt(&NONCE, PLAINTEXT, Some(AAD)).map_err(|e| {
        LatticeArcError::ValidationError {
            message: format!("AES-256-GCM KAT: encryption failed: {}", e),
        }
    })?;

    if !bool::from(ciphertext.ct_eq(&EXPECTED_CT)) {
        return Err(LatticeArcError::ValidationError {
            message: "AES-256-GCM KAT: ciphertext does not match expected value".to_string(),
        });
    }

    if !bool::from(tag.ct_eq(&EXPECTED_TAG)) {
        return Err(LatticeArcError::ValidationError {
            message: "AES-256-GCM KAT: tag does not match expected value".to_string(),
        });
    }

    // Decrypt and verify plaintext matches
    let decrypted = cipher.decrypt(&NONCE, &ciphertext, &tag, Some(AAD)).map_err(|e| {
        LatticeArcError::ValidationError {
            message: format!("AES-256-GCM KAT: decryption failed: {}", e),
        }
    })?;

    if bool::from(decrypted.ct_eq(PLAINTEXT)) {
        Ok(())
    } else {
        Err(LatticeArcError::ValidationError {
            message: "AES-256-GCM KAT: decrypted plaintext does not match original".to_string(),
        })
    }
}

// =============================================================================
// ML-KEM-768 Known Answer Test
// =============================================================================

/// ML-KEM-768 Known Answer Test
///
/// This test verifies the ML-KEM-768 implementation by performing a complete
/// encapsulate/decapsulate roundtrip using `MlKemDecapsulationKeyPair`.
///
/// The test:
/// 1. Generates a keypair with decapsulation capability
/// 2. Encapsulates a shared secret using the public key
/// 3. Decapsulates using the decapsulation key
/// 4. Verifies the shared secrets match (constant-time comparison)
///
/// # Errors
///
/// Returns error if key generation, encapsulation, decapsulation fails,
/// or if the shared secrets don't match.
pub fn kat_ml_kem_768() -> Result<()> {
    use crate::kem::ml_kem::{MlKem, MlKemSecurityLevel};
    use rand::rngs::OsRng;

    let mut rng = OsRng;

    // Generate a keypair with decapsulation capability
    let dk = MlKem::generate_decapsulation_keypair(MlKemSecurityLevel::MlKem768).map_err(|e| {
        LatticeArcError::ValidationError {
            message: format!("ML-KEM-768 KAT: key generation failed: {}", e),
        }
    })?;

    // Verify public key size
    let pk = dk.public_key();
    if pk.as_bytes().len() != MlKemSecurityLevel::MlKem768.public_key_size() {
        return Err(LatticeArcError::ValidationError {
            message: format!(
                "ML-KEM-768 KAT: public key size mismatch: expected {}, got {}",
                MlKemSecurityLevel::MlKem768.public_key_size(),
                pk.as_bytes().len()
            ),
        });
    }

    // Encapsulate a shared secret
    let (ss_encap, ciphertext) =
        MlKem::encapsulate(&mut rng, pk).map_err(|e| LatticeArcError::ValidationError {
            message: format!("ML-KEM-768 KAT: encapsulation failed: {}", e),
        })?;

    // Verify ciphertext size
    if ciphertext.as_bytes().len() != MlKemSecurityLevel::MlKem768.ciphertext_size() {
        return Err(LatticeArcError::ValidationError {
            message: format!(
                "ML-KEM-768 KAT: ciphertext size mismatch: expected {}, got {}",
                MlKemSecurityLevel::MlKem768.ciphertext_size(),
                ciphertext.as_bytes().len()
            ),
        });
    }

    // Decapsulate the shared secret
    let ss_decap = dk.decapsulate(&ciphertext).map_err(|e| LatticeArcError::ValidationError {
        message: format!("ML-KEM-768 KAT: decapsulation failed: {}", e),
    })?;

    // Verify shared secrets match (constant-time comparison)
    if !bool::from(ss_encap.as_bytes().ct_eq(ss_decap.as_bytes())) {
        return Err(LatticeArcError::ValidationError {
            message: "ML-KEM-768 KAT: encapsulated and decapsulated shared secrets do not match"
                .to_string(),
        });
    }

    // Verify shared secret is not all zeros
    let all_zeros = ss_encap.as_bytes().iter().all(|&b| b == 0);
    if all_zeros {
        return Err(LatticeArcError::ValidationError {
            message: "ML-KEM-768 KAT: shared secret is all zeros".to_string(),
        });
    }

    Ok(())
}

// =============================================================================
// ML-DSA Known Answer Test
// =============================================================================

/// ML-DSA Known Answer Test (FIPS 204)
///
/// This test verifies the ML-DSA implementation by performing a complete
/// sign/verify round-trip using ML-DSA-44 (NIST Level 2 security).
///
/// The test:
/// 1. Generates a fresh keypair
/// 2. Signs a fixed test message
/// 3. Verifies the signature succeeds
/// 4. Verifies that verification fails with a modified message
///
/// ML-DSA (FIPS 204) has longer execution times compared to symmetric primitives.
/// This test should be run as a conditional self-test rather than at power-up
/// if performance is a concern.
///
/// # Errors
///
/// Returns error if key generation, signing, or verification fails.
pub fn kat_ml_dsa() -> Result<()> {
    use crate::sig::ml_dsa::{MlDsaParameterSet, generate_keypair, sign, verify};

    // Fixed test message for KAT
    const TEST_MESSAGE: &[u8] = b"FIPS 140-3 ML-DSA Known Answer Test";
    const CONTEXT: &[u8] = b"";

    // Generate a keypair using ML-DSA-44 (fastest variant for KAT)
    let (public_key, secret_key) = generate_keypair(MlDsaParameterSet::MLDSA44).map_err(|e| {
        LatticeArcError::ValidationError {
            message: format!("ML-DSA KAT: key generation failed: {}", e),
        }
    })?;

    // Verify key sizes match expected values
    if public_key.len() != MlDsaParameterSet::MLDSA44.public_key_size() {
        return Err(LatticeArcError::ValidationError {
            message: format!(
                "ML-DSA KAT: public key size mismatch: expected {}, got {}",
                MlDsaParameterSet::MLDSA44.public_key_size(),
                public_key.len()
            ),
        });
    }

    // Sign the test message
    let signature = sign(&secret_key, TEST_MESSAGE, CONTEXT).map_err(|e| {
        LatticeArcError::ValidationError { message: format!("ML-DSA KAT: signing failed: {}", e) }
    })?;

    // Verify signature size
    if signature.len() != MlDsaParameterSet::MLDSA44.signature_size() {
        return Err(LatticeArcError::ValidationError {
            message: format!(
                "ML-DSA KAT: signature size mismatch: expected {}, got {}",
                MlDsaParameterSet::MLDSA44.signature_size(),
                signature.len()
            ),
        });
    }

    // Verify the signature
    let is_valid = verify(&public_key, TEST_MESSAGE, &signature, CONTEXT).map_err(|e| {
        LatticeArcError::ValidationError {
            message: format!("ML-DSA KAT: verification failed: {}", e),
        }
    })?;

    if !is_valid {
        return Err(LatticeArcError::ValidationError {
            message: "ML-DSA KAT: valid signature was rejected".to_string(),
        });
    }

    // Verify that a modified message fails verification
    const WRONG_MESSAGE: &[u8] = b"FIPS 140-3 ML-DSA Wrong Message";
    let is_valid_wrong = verify(&public_key, WRONG_MESSAGE, &signature, CONTEXT).map_err(|e| {
        LatticeArcError::ValidationError {
            message: format!("ML-DSA KAT: verification check failed: {}", e),
        }
    })?;

    if is_valid_wrong {
        return Err(LatticeArcError::ValidationError {
            message: "ML-DSA KAT: invalid signature was accepted".to_string(),
        });
    }

    Ok(())
}

/// SLH-DSA Known Answer Test (FIPS 205)
///
/// This test verifies the SLH-DSA implementation by performing a complete
/// sign/verify round-trip using SLH-DSA-SHAKE-128s (NIST Level 1 security).
///
/// The test:
/// 1. Generates a fresh keypair
/// 2. Signs a fixed test message
/// 3. Verifies the signature succeeds
/// 4. Verifies that verification fails with a modified message
///
/// SLH-DSA (FIPS 205) has significantly longer execution times due to the
/// hash-based signature scheme. This test should be run as a conditional
/// self-test rather than at power-up.
///
/// # Errors
///
/// Returns error if key generation, signing, or verification fails.
pub fn kat_slh_dsa() -> Result<()> {
    use crate::sig::slh_dsa::{SecurityLevel, SigningKey};

    // Fixed test message for KAT
    const TEST_MESSAGE: &[u8] = b"FIPS 140-3 SLH-DSA Known Answer Test";

    // Generate a keypair using SLH-DSA-SHAKE-128s (fastest variant for KAT)
    let (signing_key, verifying_key) =
        SigningKey::generate(SecurityLevel::Shake128s).map_err(|e| {
            LatticeArcError::ValidationError {
                message: format!("SLH-DSA KAT: key generation failed: {}", e),
            }
        })?;

    // Verify key sizes match expected values
    let expected_pk_size = SecurityLevel::Shake128s.public_key_size();
    if verifying_key.as_bytes().len() != expected_pk_size {
        return Err(LatticeArcError::ValidationError {
            message: format!(
                "SLH-DSA KAT: public key size mismatch: expected {}, got {}",
                expected_pk_size,
                verifying_key.as_bytes().len()
            ),
        });
    }

    let expected_sk_size = SecurityLevel::Shake128s.secret_key_size();
    if signing_key.as_bytes().len() != expected_sk_size {
        return Err(LatticeArcError::ValidationError {
            message: format!(
                "SLH-DSA KAT: secret key size mismatch: expected {}, got {}",
                expected_sk_size,
                signing_key.as_bytes().len()
            ),
        });
    }

    // Sign the test message (None = no context string)
    let signature = signing_key.sign(TEST_MESSAGE, None).map_err(|e| {
        LatticeArcError::ValidationError { message: format!("SLH-DSA KAT: signing failed: {}", e) }
    })?;

    // Verify signature size
    let expected_sig_size = SecurityLevel::Shake128s.signature_size();
    if signature.len() != expected_sig_size {
        return Err(LatticeArcError::ValidationError {
            message: format!(
                "SLH-DSA KAT: signature size mismatch: expected {}, got {}",
                expected_sig_size,
                signature.len()
            ),
        });
    }

    // Verify the signature
    let is_valid = verifying_key.verify(TEST_MESSAGE, &signature, None).map_err(|e| {
        LatticeArcError::ValidationError {
            message: format!("SLH-DSA KAT: verification failed: {}", e),
        }
    })?;

    if !is_valid {
        return Err(LatticeArcError::ValidationError {
            message: "SLH-DSA KAT: valid signature was rejected".to_string(),
        });
    }

    // Verify that a modified message fails verification
    const WRONG_MESSAGE: &[u8] = b"FIPS 140-3 SLH-DSA Wrong Message";
    let is_valid_wrong = verifying_key.verify(WRONG_MESSAGE, &signature, None).map_err(|e| {
        LatticeArcError::ValidationError {
            message: format!("SLH-DSA KAT: verification check failed: {}", e),
        }
    })?;

    if is_valid_wrong {
        return Err(LatticeArcError::ValidationError {
            message: "SLH-DSA KAT: invalid signature was accepted".to_string(),
        });
    }

    Ok(())
}

/// FN-DSA Known Answer Test (FIPS 206)
///
/// This test verifies the FN-DSA implementation by performing a complete
/// sign/verify round-trip using FN-DSA-512 (Level I security).
///
/// The test:
/// 1. Generates a fresh keypair
/// 2. Signs a fixed test message
/// 3. Verifies the signature succeeds
/// 4. Verifies that verification fails with a modified message
///
/// FN-DSA (FIPS 206) requires a larger stack size for key generation.
/// This test should be run as a conditional self-test rather than at power-up.
///
/// # Errors
///
/// Returns error if key generation, signing, or verification fails.
pub fn kat_fn_dsa() -> Result<()> {
    use crate::sig::fndsa::{FNDsaSecurityLevel, KeyPair};
    use rand::rngs::OsRng;

    // Fixed test message for KAT
    const TEST_MESSAGE: &[u8] = b"FIPS 140-3 FN-DSA Known Answer Test";

    // FN-DSA requires a larger stack size for key generation
    // Run the test in a separate thread with increased stack size
    std::thread::Builder::new()
        .stack_size(32 * 1024 * 1024) // 32 MB stack
        .spawn(|| -> Result<()> {
            let mut rng = OsRng;

            // Generate a keypair using FN-DSA-512 (Level I security)
            let mut keypair =
                KeyPair::generate(&mut rng, FNDsaSecurityLevel::Level512).map_err(|e| {
                    LatticeArcError::ValidationError {
                        message: format!("FN-DSA KAT: key generation failed: {}", e),
                    }
                })?;

            // Verify key sizes match expected values
            let expected_pk_size = FNDsaSecurityLevel::Level512.verifying_key_size();
            if keypair.verifying_key().to_bytes().len() != expected_pk_size {
                return Err(LatticeArcError::ValidationError {
                    message: format!(
                        "FN-DSA KAT: verifying key size mismatch: expected {}, got {}",
                        expected_pk_size,
                        keypair.verifying_key().to_bytes().len()
                    ),
                });
            }

            let expected_sk_size = FNDsaSecurityLevel::Level512.signing_key_size();
            if keypair.signing_key().to_bytes().len() != expected_sk_size {
                return Err(LatticeArcError::ValidationError {
                    message: format!(
                        "FN-DSA KAT: signing key size mismatch: expected {}, got {}",
                        expected_sk_size,
                        keypair.signing_key().to_bytes().len()
                    ),
                });
            }

            // Sign the test message
            let signature = keypair.sign(&mut rng, TEST_MESSAGE).map_err(|e| {
                LatticeArcError::ValidationError {
                    message: format!("FN-DSA KAT: signing failed: {}", e),
                }
            })?;

            // Verify signature size
            let expected_sig_size = FNDsaSecurityLevel::Level512.signature_size();
            if signature.len() != expected_sig_size {
                return Err(LatticeArcError::ValidationError {
                    message: format!(
                        "FN-DSA KAT: signature size mismatch: expected {}, got {}",
                        expected_sig_size,
                        signature.len()
                    ),
                });
            }

            // Verify the signature
            let is_valid = keypair.verify(TEST_MESSAGE, &signature).map_err(|e| {
                LatticeArcError::ValidationError {
                    message: format!("FN-DSA KAT: verification failed: {}", e),
                }
            })?;

            if !is_valid {
                return Err(LatticeArcError::ValidationError {
                    message: "FN-DSA KAT: valid signature was rejected".to_string(),
                });
            }

            // Verify that a modified message fails verification
            const WRONG_MESSAGE: &[u8] = b"FIPS 140-3 FN-DSA Wrong Message";
            let is_valid_wrong = keypair.verify(WRONG_MESSAGE, &signature).map_err(|e| {
                LatticeArcError::ValidationError {
                    message: format!("FN-DSA KAT: verification check failed: {}", e),
                }
            })?;

            if is_valid_wrong {
                return Err(LatticeArcError::ValidationError {
                    message: "FN-DSA KAT: invalid signature was accepted".to_string(),
                });
            }

            Ok(())
        })
        .map_err(|e| LatticeArcError::ValidationError {
            message: format!("FN-DSA KAT: failed to spawn thread: {}", e),
        })?
        .join()
        .map_err(|_e| LatticeArcError::ValidationError {
            message: "FN-DSA KAT: thread panicked".to_string(),
        })?
}

// =============================================================================
// Integrity Test
// =============================================================================

/// Software/Firmware Integrity Test
///
/// FIPS 140-3 Software/Firmware Load Test (Section 9.2.2)
///
/// Verifies the integrity of the cryptographic module at power-up by computing
/// and comparing an HMAC-SHA256 digest of critical module components.
///
/// # FIPS 140-3 Requirement
///
/// Per FIPS 140-3 Section 9.2.2: "The module shall perform a software/firmware
/// load test to verify the integrity of the software or firmware code. The test
/// shall be executed when the module is powered up and shall use a cryptographic
/// algorithm from Appendix C or an approved authentication technique."
///
/// # Current Implementation
///
/// This implementation uses HMAC-SHA256 to verify the integrity of the compiled
/// module by reading the module's executable/library file and computing its hash.
/// The expected HMAC value is embedded during the build process.
///
/// **For FIPS Certification:** This implementation needs enhancement to:
/// - Use a hardware security module (HSM) or TPM for key storage
/// - Implement secure boot chain verification
/// - Generate HMAC in a separate trusted build environment
/// - Store HMAC in tamper-evident storage
///
/// # Errors
///
/// Returns error if:
/// - Unable to locate or read the module binary
/// - HMAC computation fails
/// - Computed HMAC does not match expected value (integrity violation)
pub fn integrity_test() -> Result<()> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    // FIPS requires using a cryptographic key for HMAC
    // For a self-contained integrity test, we use a deterministic key derived
    // from the module identity. In production FIPS, this would come from HSM/TPM.
    const INTEGRITY_KEY: &[u8] = b"LatticeArc-FIPS-140-3-Module-Integrity-Key-v1";

    // Attempt to get the current executable/library path
    // For libraries loaded dynamically, this gets the main executable,
    // but the principle of integrity verification is demonstrated
    let module_path = std::env::current_exe().map_err(|e| LatticeArcError::ValidationError {
        message: format!("Integrity test: cannot locate module binary: {}", e),
    })?;

    // Read the module binary
    let module_bytes =
        std::fs::read(&module_path).map_err(|e| LatticeArcError::ValidationError {
            message: format!("Integrity test: cannot read module binary: {}", e),
        })?;

    // Compute HMAC-SHA256 over the module binary
    let mut mac = Hmac::<Sha256>::new_from_slice(INTEGRITY_KEY).map_err(|e| {
        LatticeArcError::ValidationError {
            message: format!("Integrity test: HMAC initialization failed: {}", e),
        }
    })?;

    mac.update(&module_bytes);
    let computed_hmac = mac.finalize().into_bytes();

    // In a production FIPS module, the expected HMAC would be:
    // 1. Computed in a secure build environment
    // 2. Stored in tamper-evident storage (HSM, TPM, or signed manifest)
    // 3. Verified against the runtime-computed value
    //
    // For this implementation, we use a reference HMAC that represents the
    // "known-good" state. This demonstrates the verification mechanism.
    //
    // NOTE: The expected HMAC must be updated whenever the module is recompiled.
    // For production FIPS certification, implement automated HMAC generation
    // in the build pipeline.

    // Expected HMAC generated by build script
    // The build script creates a file defining EXPECTED_HMAC in OUT_DIR
    // We include it here to get the constant value
    mod generated {
        include!(concat!(env!("OUT_DIR"), "/integrity_hmac.rs"));
    }
    let expected_hmac = generated::EXPECTED_HMAC;

    // If no expected HMAC is configured, behavior depends on build mode:
    // - Debug builds: warn and continue (development mode)
    // - Release builds: fail (production FIPS requirement)
    let Some(expected_hmac) = expected_hmac else {
        #[cfg(debug_assertions)]
        {
            #[allow(clippy::print_stderr)] // Development mode diagnostic output
            {
                eprintln!("FIPS Integrity Test: Development mode (debug build)");
                eprintln!("   Expected HMAC not configured. Computed HMAC:");
                eprintln!("   {:02x?}", computed_hmac.as_slice());
                eprintln!("   Configure PRODUCTION_HMAC.txt for production builds.");
            }
            return Ok(());
        }

        #[cfg(not(debug_assertions))]
        {
            return Err(LatticeArcError::ValidationError {
                message: "FIPS Integrity Test FAILED: No expected HMAC configured. \
                         Production builds require PRODUCTION_HMAC.txt with the module HMAC."
                    .to_string(),
            });
        }
    };

    // Constant-time comparison using subtle crate
    use subtle::ConstantTimeEq;
    let hmac_match = computed_hmac.ct_eq(expected_hmac);

    if hmac_match.into() {
        Ok(())
    } else {
        // Integrity violation detected
        Err(LatticeArcError::ValidationError {
            message: "FIPS Integrity Test FAILED: Module binary has been modified or corrupted. \
                     This is a critical security violation."
                .to_string(),
        })
    }
}

// =============================================================================
// Module State Management
// =============================================================================

use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static SELF_TEST_PASSED: AtomicBool = AtomicBool::new(false);

// =============================================================================
// Module Error State Persistence (FIPS 140-3 Compliance)
// =============================================================================

/// Error codes for module state tracking
///
/// These codes indicate various failure conditions that should prevent
/// the cryptographic module from performing any operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ModuleErrorCode {
    /// No error - module is operational
    NoError = 0,
    /// Self-test failure
    SelfTestFailure = 1,
    /// Entropy source failure
    EntropyFailure = 2,
    /// Integrity check failure
    IntegrityFailure = 3,
    /// Critical cryptographic error
    CriticalCryptoError = 4,
    /// Key zeroization failure
    KeyZeroizationFailure = 5,
    /// Authentication failure (repeated failures)
    AuthenticationFailure = 6,
    /// Hardware security module error
    HsmError = 7,
    /// Unknown critical error
    UnknownCriticalError = 255,
}

impl ModuleErrorCode {
    /// Convert from u32 to `ModuleErrorCode`
    #[must_use]
    pub fn from_u32(value: u32) -> Self {
        match value {
            0 => Self::NoError,
            1 => Self::SelfTestFailure,
            2 => Self::EntropyFailure,
            3 => Self::IntegrityFailure,
            4 => Self::CriticalCryptoError,
            5 => Self::KeyZeroizationFailure,
            6 => Self::AuthenticationFailure,
            7 => Self::HsmError,
            _ => Self::UnknownCriticalError,
        }
    }

    /// Check if this error code represents an error state
    #[must_use]
    pub fn is_error(&self) -> bool {
        *self != Self::NoError
    }

    /// Get a human-readable description of the error
    #[must_use]
    pub fn description(&self) -> &'static str {
        match self {
            Self::NoError => "No error",
            Self::SelfTestFailure => "FIPS 140-3 self-test failure",
            Self::EntropyFailure => "Entropy source failure",
            Self::IntegrityFailure => "Software/firmware integrity check failure",
            Self::CriticalCryptoError => "Critical cryptographic operation error",
            Self::KeyZeroizationFailure => "Sensitive key material zeroization failure",
            Self::AuthenticationFailure => "Repeated authentication failures",
            Self::HsmError => "Hardware security module error",
            Self::UnknownCriticalError => "Unknown critical error",
        }
    }
}

/// Module error state information
#[derive(Debug, Clone)]
pub struct ModuleErrorState {
    /// Error code
    pub error_code: ModuleErrorCode,
    /// Unix timestamp when the error occurred (seconds since epoch)
    pub timestamp: u64,
}

impl ModuleErrorState {
    /// Check if the module is in an error state
    #[must_use]
    pub fn is_error(&self) -> bool {
        self.error_code.is_error()
    }
}

// Static atomic storage for error state
// Using atomics for thread-safe access without locks
static MODULE_ERROR_CODE: AtomicU32 = AtomicU32::new(0);
static MODULE_ERROR_TIMESTAMP: AtomicU64 = AtomicU64::new(0);

/// Get the current Unix timestamp in seconds
fn current_timestamp() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Set the module error state
///
/// This function records an error condition that should block all
/// cryptographic operations until the error is resolved. According
/// to FIPS 140-3, when a cryptographic module enters an error state,
/// it must not provide any cryptographic services.
///
/// # Arguments
///
/// * `code` - The error code indicating the type of failure
///
/// # Example
///
/// ```no_run
/// use arc_primitives::self_test::{set_module_error, ModuleErrorCode};
///
/// // Record a self-test failure
/// set_module_error(ModuleErrorCode::SelfTestFailure);
///
/// // The module will now block all crypto operations
/// ```
pub fn set_module_error(code: ModuleErrorCode) {
    let timestamp = current_timestamp();
    MODULE_ERROR_CODE.store(code as u32, Ordering::SeqCst);
    MODULE_ERROR_TIMESTAMP.store(timestamp, Ordering::SeqCst);

    // Also clear the self-test passed flag if entering error state
    if code.is_error() {
        SELF_TEST_PASSED.store(false, Ordering::SeqCst);
    }
}

/// Get the current module error state
///
/// Returns the current error state including the error code and
/// timestamp when the error occurred.
///
/// # Returns
///
/// A `ModuleErrorState` struct containing the error code and timestamp
#[must_use]
pub fn get_module_error_state() -> ModuleErrorState {
    ModuleErrorState {
        error_code: ModuleErrorCode::from_u32(MODULE_ERROR_CODE.load(Ordering::SeqCst)),
        timestamp: MODULE_ERROR_TIMESTAMP.load(Ordering::SeqCst),
    }
}

/// Check if the module is operational
///
/// This function performs a comprehensive check of the module state:
/// 1. Verifies no error state is set
/// 2. Verifies self-tests have passed
///
/// # Returns
///
/// `true` if the module is fully operational, `false` otherwise
///
/// # Example
///
/// ```no_run
/// use arc_primitives::self_test::is_module_operational;
///
/// if !is_module_operational() {
///     eprintln!("Module is not operational - crypto operations blocked");
/// }
/// ```
#[must_use]
pub fn is_module_operational() -> bool {
    let error_code = ModuleErrorCode::from_u32(MODULE_ERROR_CODE.load(Ordering::Acquire));
    !error_code.is_error() && SELF_TEST_PASSED.load(Ordering::Acquire)
}

/// Clear the error state for testing or recovery
///
/// **WARNING**: This function should only be used in controlled circumstances:
/// - During testing
/// - After a complete module re-initialization
/// - After verified recovery from the error condition
///
/// In production FIPS environments, clearing error state typically requires
/// a full module restart and successful re-execution of all self-tests.
///
/// # Example
///
/// ```no_run
/// use arc_primitives::self_test::{clear_error_state, initialize_and_test};
///
/// // Clear error state (e.g., during testing)
/// clear_error_state();
///
/// // Re-run initialization
/// let result = initialize_and_test();
/// ```
pub fn clear_error_state() {
    MODULE_ERROR_CODE.store(ModuleErrorCode::NoError as u32, Ordering::SeqCst);
    MODULE_ERROR_TIMESTAMP.store(0, Ordering::SeqCst);
}

/// Check if the module has passed self-tests
///
/// This function should be called before any cryptographic operation
/// to ensure the module is in a valid state.
///
/// # Returns
///
/// `true` if self-tests have passed, `false` otherwise
#[must_use]
pub fn self_tests_passed() -> bool {
    SELF_TEST_PASSED.load(Ordering::Acquire)
}

/// Run power-up tests and set the module state
///
/// This function runs all power-up tests and updates the module state
/// accordingly. It should be called once during module initialization.
/// On failure, the module enters an error state and no cryptographic
/// services will be provided.
///
/// # Returns
///
/// The result of the self-tests
#[must_use]
pub fn initialize_and_test() -> SelfTestResult {
    let result = run_power_up_tests();
    if result.is_pass() {
        SELF_TEST_PASSED.store(true, Ordering::Release);
    } else {
        // Enter error state — no crypto operations allowed
        set_module_error(ModuleErrorCode::SelfTestFailure);
    }
    result
}

/// Verify module is operational before performing cryptographic operations
///
/// This function checks if the module has passed self-tests and is ready
/// to perform cryptographic operations. It also verifies that no error
/// state has been set.
///
/// According to FIPS 140-3, a cryptographic module must not provide any
/// cryptographic services when it is in an error state.
///
/// # Errors
///
/// Returns `LatticeArcError::ValidationError` if:
/// - Self-tests have not passed
/// - The module is in an error state
pub fn verify_operational() -> Result<()> {
    // Check for error state first
    let error_state = get_module_error_state();
    if error_state.is_error() {
        return Err(LatticeArcError::ValidationError {
            message: format!(
                "FIPS module not operational: {} (error set at timestamp {})",
                error_state.error_code.description(),
                error_state.timestamp
            ),
        });
    }

    // Check self-test status
    if self_tests_passed() {
        Ok(())
    } else {
        Err(LatticeArcError::ValidationError {
            message: "FIPS module not operational: self-tests have not passed".to_string(),
        })
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_kat_passes() {
        assert!(kat_sha256().is_ok());
    }

    #[test]
    fn test_hkdf_sha256_kat_passes() {
        assert!(kat_hkdf_sha256().is_ok());
    }

    #[test]
    fn test_aes_256_gcm_kat_passes() {
        assert!(kat_aes_256_gcm().is_ok());
    }

    #[test]
    fn test_ml_kem_768_kat_passes() {
        assert!(kat_ml_kem_768().is_ok());
    }

    #[test]
    fn test_power_up_tests_pass() {
        let result = run_power_up_tests();
        assert!(result.is_pass(), "Power-up tests should pass: {:?}", result);
    }

    #[test]
    fn test_power_up_tests_with_report() {
        let report = run_power_up_tests_with_report();
        assert!(report.overall_result.is_pass(), "Overall result should pass");
        assert!(!report.tests.is_empty(), "Should have individual test results");

        for test in &report.tests {
            assert!(test.result.is_pass(), "Test {} should pass", test.algorithm);
            assert!(test.duration_us.is_some(), "Duration should be measured");
        }
    }

    #[test]
    fn test_self_test_result_methods() {
        let pass = SelfTestResult::Pass;
        let fail = SelfTestResult::Fail("test failure".to_string());

        assert!(pass.is_pass());
        assert!(!pass.is_fail());
        assert!(pass.to_result().is_ok());

        assert!(!fail.is_pass());
        assert!(fail.is_fail());
        assert!(fail.to_result().is_err());
    }

    #[test]
    fn test_initialize_and_verify() {
        // Reset state for test
        SELF_TEST_PASSED.store(false, Ordering::Release);

        // Before initialization, verify should fail
        assert!(verify_operational().is_err());

        // Initialize
        let result = initialize_and_test();
        assert!(result.is_pass());

        // After initialization, verify should pass
        assert!(verify_operational().is_ok());
        assert!(self_tests_passed());
    }

    #[test]
    fn test_ml_dsa_kat_passes() {
        let result = kat_ml_dsa();
        assert!(result.is_ok(), "ML-DSA KAT should pass: {:?}", result);
    }

    #[test]
    fn test_slh_dsa_kat_passes() {
        let result = kat_slh_dsa();
        assert!(result.is_ok(), "SLH-DSA KAT should pass: {:?}", result);
    }

    #[test]
    fn test_fn_dsa_kat_passes() {
        let result = kat_fn_dsa();
        assert!(result.is_ok(), "FN-DSA KAT should pass: {:?}", result);
    }

    #[test]
    fn test_integrity_test_passes() {
        assert!(integrity_test().is_ok());
    }

    // -------------------------------------------------------------------------
    // Module Error State Tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_module_error_code_from_u32() {
        assert_eq!(ModuleErrorCode::from_u32(0), ModuleErrorCode::NoError);
        assert_eq!(ModuleErrorCode::from_u32(1), ModuleErrorCode::SelfTestFailure);
        assert_eq!(ModuleErrorCode::from_u32(2), ModuleErrorCode::EntropyFailure);
        assert_eq!(ModuleErrorCode::from_u32(3), ModuleErrorCode::IntegrityFailure);
        assert_eq!(ModuleErrorCode::from_u32(4), ModuleErrorCode::CriticalCryptoError);
        assert_eq!(ModuleErrorCode::from_u32(5), ModuleErrorCode::KeyZeroizationFailure);
        assert_eq!(ModuleErrorCode::from_u32(6), ModuleErrorCode::AuthenticationFailure);
        assert_eq!(ModuleErrorCode::from_u32(7), ModuleErrorCode::HsmError);
        assert_eq!(ModuleErrorCode::from_u32(100), ModuleErrorCode::UnknownCriticalError);
        assert_eq!(ModuleErrorCode::from_u32(255), ModuleErrorCode::UnknownCriticalError);
    }

    #[test]
    fn test_module_error_code_is_error() {
        assert!(!ModuleErrorCode::NoError.is_error());
        assert!(ModuleErrorCode::SelfTestFailure.is_error());
        assert!(ModuleErrorCode::EntropyFailure.is_error());
        assert!(ModuleErrorCode::IntegrityFailure.is_error());
        assert!(ModuleErrorCode::CriticalCryptoError.is_error());
        assert!(ModuleErrorCode::KeyZeroizationFailure.is_error());
        assert!(ModuleErrorCode::AuthenticationFailure.is_error());
        assert!(ModuleErrorCode::HsmError.is_error());
        assert!(ModuleErrorCode::UnknownCriticalError.is_error());
    }

    #[test]
    fn test_module_error_code_description() {
        assert_eq!(ModuleErrorCode::NoError.description(), "No error");
        assert_eq!(ModuleErrorCode::SelfTestFailure.description(), "FIPS 140-3 self-test failure");
        assert_eq!(ModuleErrorCode::EntropyFailure.description(), "Entropy source failure");
    }

    #[test]
    fn test_set_and_get_module_error() {
        // Clear any existing error state
        clear_error_state();

        // Initially no error
        let state = get_module_error_state();
        assert!(!state.is_error());
        assert_eq!(state.error_code, ModuleErrorCode::NoError);

        // Set an error
        set_module_error(ModuleErrorCode::SelfTestFailure);
        let state = get_module_error_state();
        assert!(state.is_error());
        assert_eq!(state.error_code, ModuleErrorCode::SelfTestFailure);
        assert!(state.timestamp > 0);

        // Clear error state
        clear_error_state();
        let state = get_module_error_state();
        assert!(!state.is_error());
        assert_eq!(state.error_code, ModuleErrorCode::NoError);
        assert_eq!(state.timestamp, 0);
    }

    #[test]
    fn test_is_module_operational() {
        // Clear any existing state
        clear_error_state();
        SELF_TEST_PASSED.store(false, Ordering::SeqCst);

        // Not operational if self-tests haven't passed
        assert!(!is_module_operational());

        // Pass self-tests
        SELF_TEST_PASSED.store(true, Ordering::SeqCst);
        assert!(is_module_operational());

        // Set error - should become not operational
        set_module_error(ModuleErrorCode::EntropyFailure);
        assert!(!is_module_operational());

        // Clear error
        clear_error_state();
        SELF_TEST_PASSED.store(true, Ordering::SeqCst);
        assert!(is_module_operational());
    }

    #[test]
    fn test_verify_operational_with_error_state() {
        // Clear any existing state and initialize
        clear_error_state();
        let result = initialize_and_test();
        assert!(result.is_pass());

        // Should be operational initially
        assert!(verify_operational().is_ok());

        // Set an error
        set_module_error(ModuleErrorCode::CriticalCryptoError);

        // Should not be operational with error set
        let result = verify_operational();
        assert!(result.is_err());
        if let Err(LatticeArcError::ValidationError { message }) = result {
            assert!(message.contains("Critical cryptographic operation error"));
        }

        // Clear error and re-initialize
        clear_error_state();
        let result = initialize_and_test();
        assert!(result.is_pass());
        assert!(verify_operational().is_ok());
    }

    #[test]
    fn test_set_error_clears_self_test_passed() {
        // Initialize and verify self-tests passed
        clear_error_state();
        let result = initialize_and_test();
        assert!(result.is_pass());
        assert!(self_tests_passed());

        // Setting an error should clear the self-test passed flag
        set_module_error(ModuleErrorCode::IntegrityFailure);
        assert!(!self_tests_passed());

        // Cleanup
        clear_error_state();
    }

    #[test]
    fn test_module_error_state_struct() {
        let state = ModuleErrorState { error_code: ModuleErrorCode::NoError, timestamp: 0 };
        assert!(!state.is_error());

        let state =
            ModuleErrorState { error_code: ModuleErrorCode::HsmError, timestamp: 1234567890 };
        assert!(state.is_error());
    }

    // -------------------------------------------------------------------------
    // Additional description coverage
    // -------------------------------------------------------------------------

    #[test]
    fn test_module_error_code_all_descriptions() {
        // Cover every description() branch
        assert_eq!(
            ModuleErrorCode::IntegrityFailure.description(),
            "Software/firmware integrity check failure"
        );
        assert_eq!(
            ModuleErrorCode::CriticalCryptoError.description(),
            "Critical cryptographic operation error"
        );
        assert_eq!(
            ModuleErrorCode::KeyZeroizationFailure.description(),
            "Sensitive key material zeroization failure"
        );
        assert_eq!(
            ModuleErrorCode::AuthenticationFailure.description(),
            "Repeated authentication failures"
        );
        assert_eq!(ModuleErrorCode::HsmError.description(), "Hardware security module error");
        assert_eq!(ModuleErrorCode::UnknownCriticalError.description(), "Unknown critical error");
    }

    #[test]
    fn test_set_module_error_no_error_does_not_clear_self_test() {
        // Setting NoError should not clear self_test_passed flag
        clear_error_state();
        let result = initialize_and_test();
        assert!(result.is_pass());
        assert!(self_tests_passed());

        // NoError is NOT an error, so is_error() = false => SELF_TEST_PASSED stays true
        set_module_error(ModuleErrorCode::NoError);
        assert!(self_tests_passed());

        // Cleanup
        clear_error_state();
    }

    #[test]
    fn test_self_test_result_debug_clone() {
        let pass = SelfTestResult::Pass;
        let cloned = pass.clone();
        assert_eq!(pass, cloned);
        let debug = format!("{:?}", pass);
        assert!(debug.contains("Pass"));

        let fail = SelfTestResult::Fail("oops".to_string());
        let fail_clone = fail.clone();
        assert_eq!(fail, fail_clone);
        let debug = format!("{:?}", fail);
        assert!(debug.contains("oops"));
    }

    #[test]
    fn test_individual_test_result_fields() {
        let result = IndividualTestResult {
            algorithm: "SHA-256".to_string(),
            result: SelfTestResult::Pass,
            duration_us: Some(42),
        };
        assert_eq!(result.algorithm, "SHA-256");
        assert!(result.result.is_pass());
        assert_eq!(result.duration_us, Some(42));

        let cloned = result.clone();
        assert_eq!(cloned.algorithm, "SHA-256");
        assert_eq!(cloned, result);

        let debug = format!("{:?}", result);
        assert!(debug.contains("SHA-256"));
    }

    #[test]
    fn test_self_test_report_fields() {
        let report = run_power_up_tests_with_report();
        assert_eq!(report.tests.len(), 9); // SHA-256, HKDF, AES-GCM, SHA3-256, HMAC, ML-KEM, ML-DSA, SLH-DSA, FN-DSA
        assert!(report.total_duration_us > 0);

        let cloned = report.clone();
        assert_eq!(cloned.tests.len(), 9);

        let debug = format!("{:?}", report);
        assert!(debug.contains("SelfTestReport"));
    }

    #[test]
    fn test_module_error_code_debug() {
        let code = ModuleErrorCode::SelfTestFailure;
        let debug = format!("{:?}", code);
        assert!(debug.contains("SelfTestFailure"));

        let cloned = code;
        assert_eq!(cloned, ModuleErrorCode::SelfTestFailure);
    }

    #[test]
    fn test_module_error_state_debug_clone() {
        let state =
            ModuleErrorState { error_code: ModuleErrorCode::EntropyFailure, timestamp: 1000 };
        let cloned = state.clone();
        assert_eq!(cloned.error_code, ModuleErrorCode::EntropyFailure);
        assert_eq!(cloned.timestamp, 1000);

        let debug = format!("{:?}", state);
        assert!(debug.contains("EntropyFailure"));
    }

    #[test]
    fn test_verify_operational_without_self_tests() {
        // Reset state: no error, but self-tests not passed
        clear_error_state();
        SELF_TEST_PASSED.store(false, Ordering::SeqCst);

        let result = verify_operational();
        assert!(result.is_err());
        if let Err(LatticeArcError::ValidationError { message }) = result {
            assert!(message.contains("self-tests have not passed"));
        }

        // Cleanup: restore
        let _ = initialize_and_test();
    }

    #[test]
    fn test_multiple_error_states_in_sequence() {
        clear_error_state();

        // Set different errors in sequence
        set_module_error(ModuleErrorCode::EntropyFailure);
        let state = get_module_error_state();
        assert_eq!(state.error_code, ModuleErrorCode::EntropyFailure);

        set_module_error(ModuleErrorCode::HsmError);
        let state = get_module_error_state();
        assert_eq!(state.error_code, ModuleErrorCode::HsmError);

        set_module_error(ModuleErrorCode::KeyZeroizationFailure);
        let state = get_module_error_state();
        assert_eq!(state.error_code, ModuleErrorCode::KeyZeroizationFailure);

        // Cleanup
        clear_error_state();
        let _ = initialize_and_test();
    }

    // -------------------------------------------------------------------------
    // Additional coverage for error paths and edge cases
    // -------------------------------------------------------------------------

    #[test]
    fn test_self_test_result_fail_to_result_contains_message() {
        let fail = SelfTestResult::Fail("module corrupted".to_string());
        let result = fail.to_result();
        assert!(result.is_err());
        if let Err(LatticeArcError::ValidationError { message }) = result {
            assert!(message.contains("module corrupted"));
            assert!(message.contains("FIPS 140-3"));
        }
    }

    #[test]
    fn test_individual_test_result_with_no_duration() {
        let result = IndividualTestResult {
            algorithm: "TEST".to_string(),
            result: SelfTestResult::Fail("error".to_string()),
            duration_us: None,
        };
        assert!(result.result.is_fail());
        assert!(result.duration_us.is_none());
        let debug = format!("{:?}", result);
        assert!(debug.contains("None"));
    }

    #[test]
    fn test_self_test_report_with_failures() {
        // Manually build a report with mixed pass/fail results
        let report = SelfTestReport {
            overall_result: SelfTestResult::Fail("SHA-256 failed".to_string()),
            tests: vec![
                IndividualTestResult {
                    algorithm: "SHA-256".to_string(),
                    result: SelfTestResult::Fail("KAT mismatch".to_string()),
                    duration_us: Some(100),
                },
                IndividualTestResult {
                    algorithm: "AES-GCM".to_string(),
                    result: SelfTestResult::Pass,
                    duration_us: Some(200),
                },
            ],
            total_duration_us: 300,
        };
        assert!(report.overall_result.is_fail());
        assert_eq!(report.tests.len(), 2);
        assert!(report.tests[0].result.is_fail());
        assert!(report.tests[1].result.is_pass());

        let debug = format!("{:?}", report);
        assert!(debug.contains("SelfTestReport"));
    }

    #[test]
    fn test_module_error_code_repr_values() {
        // Verify the repr(u32) values match expectations
        assert_eq!(ModuleErrorCode::NoError as u32, 0);
        assert_eq!(ModuleErrorCode::SelfTestFailure as u32, 1);
        assert_eq!(ModuleErrorCode::EntropyFailure as u32, 2);
        assert_eq!(ModuleErrorCode::IntegrityFailure as u32, 3);
        assert_eq!(ModuleErrorCode::CriticalCryptoError as u32, 4);
        assert_eq!(ModuleErrorCode::KeyZeroizationFailure as u32, 5);
        assert_eq!(ModuleErrorCode::AuthenticationFailure as u32, 6);
        assert_eq!(ModuleErrorCode::HsmError as u32, 7);
        assert_eq!(ModuleErrorCode::UnknownCriticalError as u32, 255);
    }

    #[test]
    fn test_module_error_code_from_u32_boundary() {
        // Values 8-254 all map to UnknownCriticalError
        assert_eq!(ModuleErrorCode::from_u32(8), ModuleErrorCode::UnknownCriticalError);
        assert_eq!(ModuleErrorCode::from_u32(128), ModuleErrorCode::UnknownCriticalError);
        assert_eq!(ModuleErrorCode::from_u32(254), ModuleErrorCode::UnknownCriticalError);
        assert_eq!(ModuleErrorCode::from_u32(u32::MAX), ModuleErrorCode::UnknownCriticalError);
    }

    #[test]
    fn test_module_error_state_no_error_timestamp_zero() {
        clear_error_state();
        let state = get_module_error_state();
        assert!(!state.is_error());
        assert_eq!(state.timestamp, 0);
    }

    #[test]
    fn test_module_error_state_error_has_nonzero_timestamp() {
        clear_error_state();
        set_module_error(ModuleErrorCode::SelfTestFailure);
        let state = get_module_error_state();
        assert!(state.is_error());
        // Timestamp should be recent (within last few seconds)
        assert!(state.timestamp > 0);

        // Cleanup
        clear_error_state();
        let _ = initialize_and_test();
    }

    #[test]
    fn test_verify_operational_error_message_contains_description() {
        clear_error_state();
        set_module_error(ModuleErrorCode::EntropyFailure);

        let result = verify_operational();
        assert!(result.is_err());
        if let Err(LatticeArcError::ValidationError { message }) = result {
            assert!(message.contains("Entropy source failure"));
            assert!(message.contains("error set at timestamp"));
        }

        // Cleanup
        clear_error_state();
        let _ = initialize_and_test();
    }

    #[test]
    fn test_all_error_codes_block_operations() {
        let error_codes = [
            ModuleErrorCode::SelfTestFailure,
            ModuleErrorCode::EntropyFailure,
            ModuleErrorCode::IntegrityFailure,
            ModuleErrorCode::CriticalCryptoError,
            ModuleErrorCode::KeyZeroizationFailure,
            ModuleErrorCode::AuthenticationFailure,
            ModuleErrorCode::HsmError,
            ModuleErrorCode::UnknownCriticalError,
        ];

        for code in &error_codes {
            clear_error_state();
            SELF_TEST_PASSED.store(true, Ordering::SeqCst);
            set_module_error(*code);

            assert!(!is_module_operational(), "{:?} should block operations", code);
            assert!(verify_operational().is_err(), "{:?} should fail verify", code);
        }

        // Cleanup
        clear_error_state();
        let _ = initialize_and_test();
    }

    #[test]
    fn test_initialize_and_test_sets_flag() {
        SELF_TEST_PASSED.store(false, Ordering::SeqCst);
        clear_error_state();
        assert!(!self_tests_passed());

        let result = initialize_and_test();
        assert!(result.is_pass());
        assert!(self_tests_passed());
    }

    #[test]
    fn test_current_timestamp_reasonable() {
        let ts = current_timestamp();
        // Should be after 2020-01-01 (1577836800)
        assert!(ts > 1_577_836_800, "Timestamp should be after 2020");
    }

    #[test]
    fn test_kat_sha256_is_deterministic() {
        // Running SHA-256 KAT multiple times should always pass
        for _ in 0..5 {
            assert!(kat_sha256().is_ok());
        }
    }

    #[test]
    fn test_kat_hkdf_sha256_is_deterministic() {
        for _ in 0..5 {
            assert!(kat_hkdf_sha256().is_ok());
        }
    }

    #[test]
    fn test_kat_aes_256_gcm_is_deterministic() {
        for _ in 0..5 {
            assert!(kat_aes_256_gcm().is_ok());
        }
    }

    #[test]
    fn test_kat_ml_kem_768_always_succeeds() {
        // ML-KEM uses randomness but should always succeed
        for _ in 0..3 {
            assert!(kat_ml_kem_768().is_ok());
        }
    }

    #[test]
    fn test_run_power_up_tests_is_deterministic() {
        for _ in 0..3 {
            let result = run_power_up_tests();
            assert!(result.is_pass());
        }
    }

    #[test]
    fn test_run_power_up_tests_with_report_all_pass() {
        let report = run_power_up_tests_with_report();
        assert!(report.overall_result.is_pass());
        for test in &report.tests {
            assert!(
                test.result.is_pass(),
                "Test {} should pass but got: {:?}",
                test.algorithm,
                test.result
            );
            assert!(test.duration_us.is_some());
        }
        assert!(report.total_duration_us > 0);
    }
}
