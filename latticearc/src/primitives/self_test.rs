//! FIPS 140-3 Self-Test Module
//!
//! This module provides power-up and conditional self-tests for FIPS 140-3 compliance.
//! According to FIPS 140-3 IG 10.3.A, cryptographic modules must perform Known Answer
//! Tests (KATs) at power-up before any cryptographic operation can be performed.
//!
//! This is the **canonical** FIPS 140-3 self-test module for the LatticeArc
//! cryptographic module. The `latticearc-tests` workspace crate provides test/validation
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
//! - FN-DSA-512: Lattice-based signatures (draft FIPS 206)
//!
//! ## Usage
//!
//! ```no_run
//! use latticearc::primitives::self_test::run_power_up_tests;
//!
//! let result = run_power_up_tests();
//! assert!(result.is_pass(), "FIPS 140-3 power-up self-tests must pass");
//! ```
//!
//! ## FIPS 140-3 Compliance Notes
//!
//! - All KATs use NIST-approved test vectors where available
//! - Test vectors are hardcoded to ensure deterministic verification
//! - Any self-test failure should result in the module entering an error state
//! - No cryptographic services should be provided after a self-test failure

#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

use crate::prelude::error::{LatticeArcError, Result};
use subtle::ConstantTimeEq;

// =============================================================================
// Self-Test Result Types
// =============================================================================

/// Result of a self-test operation
#[non_exhaustive]
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
/// use latticearc::primitives::self_test::run_power_up_tests;
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

    // 6-9. PQ algorithm self-consistency tests.
    //
    // These functions are named `roundtrip_*` because they are NOT
    // Known Answer Tests in the FIPS 140-3 §10.3.1 / CAVP sense —
    // they generate a fresh keypair (random seed) and verify a
    // roundtrip rather than comparing against precomputed test
    // vectors. A bug producing self-consistent-but-wrong output would
    // pass indefinitely.
    //
    // Real KAT validation against NIST test vectors runs in the
    // `latticearc-tests` crate at `tests/tests/nist_kat/{ml_kem,
    // ml_dsa, slh_dsa}_vectors.rs` and `tests/tests/fips_cavp.rs`.
    // Those tests are required for CAVP submission; the roundtrip
    // self-tests below provide power-on smoke coverage that the
    // algorithm chains are wired correctly.
    //
    // Promoting the power-on path to true KATs requires a
    // deterministic-keygen API that the wrapper layers don't yet
    // expose; tracked as TRK-007 in docs/TRACKING.md.

    // 6. ML-KEM-768 self-consistency (encap/decap roundtrip).
    if let Err(e) = roundtrip_ml_kem_768() {
        return SelfTestResult::Fail(format!("ML-KEM-768 roundtrip failed: {}", e));
    }

    // 7. ML-DSA-44 KAT (ACVP keygen vector + sign/verify roundtrip).
    if let Err(e) = kat_ml_dsa() {
        return SelfTestResult::Fail(format!("ML-DSA-44 KAT failed: {}", e));
    }

    // 8. SLH-DSA-SHAKE-192s KAT (ACVP keygen vector + sign/verify roundtrip).
    if let Err(e) = kat_slh_dsa() {
        return SelfTestResult::Fail(format!("SLH-DSA-SHAKE-192s KAT failed: {}", e));
    }

    // 9. FN-DSA self-consistency (runs in separate thread with 32 MB stack).
    if let Err(e) = kat_fn_dsa() {
        return SelfTestResult::Fail(format!("FN-DSA roundtrip failed: {}", e));
    }

    // The doc example advertises this function as a standalone entry
    // point, so it must set `SELF_TEST_PASSED` itself — otherwise
    // `is_module_operational()` returns `false` after a clean Pass for
    // callers that don't go through `initialize_and_test`. `SeqCst`
    // pairs with the `SeqCst` loads on the reader side and gives a
    // single total order across `SELF_TEST_PASSED` and
    // `MODULE_ERROR_CODE` — needed because the FIPS module-state
    // gate reads both atomics non-atomically.
    SELF_TEST_PASSED.store(true, Ordering::SeqCst);
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

    // ML-KEM-768 roundtrip
    let kem_start = Instant::now();
    let kem_result = match roundtrip_ml_kem_768() {
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

    // ML-DSA-44 KAT (ACVP keygen + roundtrip)
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

    // SLH-DSA-SHAKE-192s KAT (ACVP keygen) + SHAKE-128s roundtrip
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
    use crate::primitives::hash::sha256;

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
    use crate::primitives::kdf::hkdf;

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
    if bool::from(result.expose_secret().ct_eq(&EXPECTED_OKM)) {
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
    use crate::primitives::hash::sha3::sha3_256;

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
    use crate::primitives::mac::hmac::hmac_sha256;

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
    use crate::primitives::aead::{AeadCipher, aes_gcm::AesGcm256};

    // NIST CAVP AES-GCM Known Answer Test vector. Source: NIST
    // Cryptographic Algorithm Validation Program GCM Test Vectors
    // (GCMVS), file `gcmEncryptExtIV256.rsp`, Count = 12. URL:
    //   https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/CAVP-TESTING-BLOCK-CIPHER-MODES#GCMVS
    //
    // replaced the previous self-computed
    // vector with this CAVP entry to satisfy FIPS 140-3 §10.3.1's
    // requirement that power-up KATs use externally-attested vectors
    // — a self-roundtrip would pass even if encrypt and decrypt shared
    // the same bug. Count = 12 has a non-empty PT (16 bytes), so it
    // exercises both the AES round function and the CTR-mode
    // increment, which an empty-PT vector cannot reach.
    //
    //   Key   = 31bdadd96698c204aa9ce1448ea94ae1fb4a9a0b3c9d773b51bb1822666b8f22
    //   IV    = 0d18e06c7c725ac9e362e1ce
    //   PT    = 2db5168e932556f8089a0622981d017d
    //   AAD   = (empty)
    //   CT    = fa4362189661d163fcd6a56d8bf0405a
    //   Tag   = d636ac1bbedd5cc3ee727dc2ab4a9489
    const KEY: [u8; 32] = [
        0x31, 0xbd, 0xad, 0xd9, 0x66, 0x98, 0xc2, 0x04, 0xaa, 0x9c, 0xe1, 0x44, 0x8e, 0xa9, 0x4a,
        0xe1, 0xfb, 0x4a, 0x9a, 0x0b, 0x3c, 0x9d, 0x77, 0x3b, 0x51, 0xbb, 0x18, 0x22, 0x66, 0x6b,
        0x8f, 0x22,
    ];
    const NONCE: [u8; 12] =
        [0x0d, 0x18, 0xe0, 0x6c, 0x7c, 0x72, 0x5a, 0xc9, 0xe3, 0x62, 0xe1, 0xce];
    const PLAINTEXT: [u8; 16] = [
        0x2d, 0xb5, 0x16, 0x8e, 0x93, 0x25, 0x56, 0xf8, 0x08, 0x9a, 0x06, 0x22, 0x98, 0x1d, 0x01,
        0x7d,
    ];

    const EXPECTED_CT: [u8; 16] = [
        0xfa, 0x43, 0x62, 0x18, 0x96, 0x61, 0xd1, 0x63, 0xfc, 0xd6, 0xa5, 0x6d, 0x8b, 0xf0, 0x40,
        0x5a,
    ];
    const EXPECTED_TAG: [u8; 16] = [
        0xd6, 0x36, 0xac, 0x1b, 0xbe, 0xdd, 0x5c, 0xc3, 0xee, 0x72, 0x7d, 0xc2, 0xab, 0x4a, 0x94,
        0x89,
    ];

    // Create cipher instance
    let cipher = AesGcm256::new(&KEY).map_err(|e| LatticeArcError::ValidationError {
        message: format!("AES-256-GCM KAT: cipher initialization failed: {}", e),
    })?;

    // Encrypt and verify ciphertext matches expected. AAD = empty per
    // the CAVP vector definition, so we pass `None`.
    let (ciphertext, tag) =
        cipher.encrypt(&NONCE, &PLAINTEXT, None).map_err(|e| LatticeArcError::ValidationError {
            message: format!("AES-256-GCM KAT: encryption failed: {}", e),
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

    // Decrypt-side: round-trip the expected (CT, tag) back to the
    // expected plaintext to catch encrypt/decrypt asymmetry that a
    // pure encrypt-side check would miss.
    let decrypted = cipher.decrypt(&NONCE, &EXPECTED_CT, &EXPECTED_TAG, None).map_err(|e| {
        LatticeArcError::ValidationError {
            message: format!("AES-256-GCM KAT: decryption failed: {}", e),
        }
    })?;

    if bool::from(decrypted.ct_eq(&PLAINTEXT)) {
        Ok(())
    } else {
        Err(LatticeArcError::ValidationError {
            message: "AES-256-GCM KAT: decrypted plaintext does not match original".to_string(),
        })
    }
}

// =============================================================================
// PQ KAT helpers — fixed-bytes RNG for ACVP-driven keygen
// =============================================================================
//
// ML-DSA / SLH-DSA wrappers internally call `try_keygen()` (no RNG
// argument). For ACVP fixed-input KATs we bypass the wrapper and call
// `try_keygen_with_rng()` on the underlying `fips204` / `fips205`
// crates with a deterministic RNG that returns exactly the bytes the
// ACVP vector specifies. The RNG is consumed in stack order (`pop()`
// returns the last-pushed value) — the call order is tied to the
// upstream crate's `KG::try_keygen_with_rng` implementation:
//   - ML-DSA: one 32-byte fill (`xi`).
//   - SLH-DSA: three sequential 24-byte fills (`sk_seed`, `sk_prf`,
//     `pk_seed`) — push in REVERSE order.
//
// This RNG must not be exposed publicly: it is unsafe by design (any
// non-test caller would defeat keygen entropy).

#[cfg(feature = "fips-self-test")]
struct FixedBytesRng {
    /// Stack of pre-loaded byte slices. `fill_bytes` pops from the top
    /// and copies into `out`. Push values in reverse order of consumption.
    data: Vec<Vec<u8>>,
}

#[cfg(feature = "fips-self-test")]
impl FixedBytesRng {
    fn new() -> Self {
        Self { data: Vec::new() }
    }

    fn push(&mut self, bytes: &[u8]) {
        self.data.push(bytes.to_vec());
    }
}

// `RngCore::fill_bytes` is infallible by trait contract. We can't
// surface vector-exhaustion or length-mismatch as a typed error from
// inside this method, and the project lints forbid `panic!` /
// `unimplemented!` / `.expect()` in production code. Misuse therefore
// silently produces zeroed output — which the downstream
// `pk_actual == pk_expected` / `sk_actual == sk_expected` comparison
// in `kat_ml_dsa` / `kat_slh_dsa` always detects, since a zero-filled
// `xi` / `sk_seed` cannot derive the ACVP-attested keypair.
#[cfg(feature = "fips-self-test")]
impl rand_core_0_6::RngCore for FixedBytesRng {
    fn next_u32(&mut self) -> u32 {
        0
    }
    fn next_u64(&mut self) -> u64 {
        0
    }
    fn fill_bytes(&mut self, out: &mut [u8]) {
        if let Some(bytes) = self.data.pop()
            && bytes.len() == out.len()
        {
            out.copy_from_slice(&bytes);
        }
    }
    fn try_fill_bytes(&mut self, out: &mut [u8]) -> core::result::Result<(), rand_core_0_6::Error> {
        self.fill_bytes(out);
        Ok(())
    }
}

#[cfg(feature = "fips-self-test")]
impl rand_core_0_6::CryptoRng for FixedBytesRng {}

// =============================================================================
// ML-KEM-768 Known Answer Test
// =============================================================================

/// ML-KEM-768 round-trip self-consistency check.
///
/// This is **not** a Known Answer Test (KAT) — it generates a fresh
/// keypair and asserts that `decapsulate(encapsulate(pk).ct) == ss`.
/// FIPS 140-3 §10.3.1 requires power-up KATs to use externally-attested
/// fixed (key, message, output) tuples; a roundtrip passes even when
/// `encapsulate` and `decapsulate` share the same bug. See
/// [`kat_aes_256_gcm`] for a real KAT against NIST CAVP `Count=12`.
///
/// To upgrade this to a real KAT, wire ACVP `keyGen` and `encapDecap`
/// vectors from <https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values>.
///
/// # Errors
///
/// Returns error if key generation, encapsulation, decapsulation fails,
/// or if the shared secrets don't match.
pub fn roundtrip_ml_kem_768() -> Result<()> {
    use crate::primitives::kem::ml_kem::{MlKem, MlKemSecurityLevel};

    // Generate a keypair with decapsulation capability
    let dk = MlKem::generate_decapsulation_keypair(MlKemSecurityLevel::MlKem768).map_err(|e| {
        LatticeArcError::ValidationError {
            message: format!("ML-KEM-768 roundtrip: key generation failed: {}", e),
        }
    })?;

    // Verify public key size
    let pk = dk.public_key();
    if pk.as_bytes().len() != MlKemSecurityLevel::MlKem768.public_key_size() {
        return Err(LatticeArcError::ValidationError {
            message: format!(
                "ML-KEM-768 roundtrip: public key size mismatch: expected {}, got {}",
                MlKemSecurityLevel::MlKem768.public_key_size(),
                pk.as_bytes().len()
            ),
        });
    }

    // Encapsulate a shared secret
    let (ss_encap, ciphertext) =
        MlKem::encapsulate(pk).map_err(|e| LatticeArcError::ValidationError {
            message: format!("ML-KEM-768 roundtrip: encapsulation failed: {}", e),
        })?;

    // Verify ciphertext size
    if ciphertext.as_bytes().len() != MlKemSecurityLevel::MlKem768.ciphertext_size() {
        return Err(LatticeArcError::ValidationError {
            message: format!(
                "ML-KEM-768 roundtrip: ciphertext size mismatch: expected {}, got {}",
                MlKemSecurityLevel::MlKem768.ciphertext_size(),
                ciphertext.as_bytes().len()
            ),
        });
    }

    // Decapsulate the shared secret
    let ss_decap = dk.decapsulate(&ciphertext).map_err(|e| LatticeArcError::ValidationError {
        message: format!("ML-KEM-768 roundtrip: decapsulation failed: {}", e),
    })?;

    // Verify shared secrets match (constant-time comparison)
    if !bool::from(ss_encap.expose_secret().ct_eq(ss_decap.expose_secret())) {
        return Err(LatticeArcError::ValidationError {
            message:
                "ML-KEM-768 roundtrip: encapsulated and decapsulated shared secrets do not match"
                    .to_string(),
        });
    }

    // Verify shared secret is not all zeros
    let all_zeros = ss_encap.expose_secret().iter().all(|&b| b == 0);
    if all_zeros {
        return Err(LatticeArcError::ValidationError {
            message: "ML-KEM-768 roundtrip: shared secret is all zeros".to_string(),
        });
    }

    Ok(())
}

// =============================================================================
// ML-DSA Known Answer Test
// =============================================================================

/// ML-DSA-44 Known Answer Test (FIPS 204).
///
/// Drives the upstream `fips204` crate's `try_keygen_with_rng` with a
/// deterministic RNG pre-loaded with the NIST ACVP `keyGen` vector
/// `tcId=1` (parameter set `ML-DSA-44`), then asserts that the produced
/// `(pk, sk)` byte-exactly matches the ACVP-attested expected output.
/// This satisfies FIPS 140-3 §10.3.1's requirement that power-up KATs
/// use externally-attested fixed (input, output) tuples.
///
/// Vector source:
/// <https://github.com/usnistgov/ACVP-Server/blob/master/gen-val/json-files/ML-DSA-keyGen-FIPS204/internalProjection.json>
/// (mirrored in-tree by the upstream `fips204` crate).
///
/// A sign/verify roundtrip on the resulting fixed key is then run for
/// additional coverage of the sign and verify paths.
///
/// ML-DSA (FIPS 204) has longer execution times compared to symmetric primitives.
/// This check should be run as a conditional self-test rather than at power-up
/// if performance is a concern.
///
/// # Errors
///
/// Returns error if keygen output does not match the ACVP vector, or if
/// the sign/verify roundtrip on the fixed key fails.
pub fn kat_ml_dsa() -> Result<()> {
    use crate::primitives::sig::ml_dsa::{MlDsaParameterSet, generate_keypair};
    use fips204::ml_dsa_44;
    use fips204::traits::{KeyGen, SerDes};

    // ACVP ML-DSA-keyGen-FIPS204, parameter set ML-DSA-44, tcId = 1.
    const SEED: [u8; 32] = [
        0x93, 0xef, 0x2e, 0x6e, 0xf1, 0xfb, 0x08, 0x99, 0x9d, 0x14, 0x2a, 0xbe, 0x02, 0x95, 0x48,
        0x23, 0x70, 0xd3, 0xf4, 0x3b, 0xdb, 0x25, 0x4a, 0x78, 0xe2, 0xb0, 0xd5, 0x16, 0x8e, 0xca,
        0x06, 0x5f,
    ];

    let mut rng = FixedBytesRng::new();
    rng.push(&SEED);

    let (pk_act, sk_act) = ml_dsa_44::KG::try_keygen_with_rng(&mut rng).map_err(|e| {
        LatticeArcError::ValidationError {
            message: format!("ML-DSA-44 KAT: deterministic keygen failed: {e}"),
        }
    })?;
    let pk_bytes = pk_act.into_bytes();
    let sk_bytes = sk_act.into_bytes();

    // ACVP-attested expected outputs (truncated to head + tail; full
    // 1312/2560-byte arrays would dominate the source file. Comparing
    // 64 bytes total prefix + 64 bytes total suffix detects any
    // implementation drift; a wrong implementation cannot accidentally
    // match four 32-byte boundary regions of an externally-attested
    // ML-DSA-44 keypair).
    const PK_HEAD: [u8; 32] = [
        0xbc, 0x5f, 0xf8, 0x10, 0xeb, 0x08, 0x90, 0x48, 0xb8, 0xab, 0x30, 0x20, 0xa7, 0xbd, 0x3b,
        0x16, 0xc0, 0xe0, 0xca, 0x3d, 0x6b, 0x97, 0xe4, 0x64, 0x6c, 0x2c, 0xca, 0xe0, 0xbb, 0xf1,
        0x9e, 0xf7,
    ];
    const PK_TAIL: [u8; 32] = [
        0x50, 0x33, 0x2f, 0xaf, 0x1a, 0xc2, 0x19, 0x1e, 0x71, 0x71, 0x25, 0xf6, 0x3e, 0x25, 0x86,
        0xc4, 0xd8, 0x6d, 0xca, 0x6b, 0xcd, 0x3d, 0x03, 0x8f, 0x9d, 0x3a, 0x7b, 0x66, 0xcb, 0xc7,
        0xdf, 0x34,
    ];
    const SK_HEAD: [u8; 32] = [
        0xbc, 0x5f, 0xf8, 0x10, 0xeb, 0x08, 0x90, 0x48, 0xb8, 0xab, 0x30, 0x20, 0xa7, 0xbd, 0x3b,
        0x16, 0xc0, 0xe0, 0xca, 0x3d, 0x6b, 0x97, 0xe4, 0x64, 0x6c, 0x2c, 0xca, 0xe0, 0xbb, 0xf1,
        0x9e, 0xf7,
    ];
    const SK_TAIL: [u8; 32] = [
        0x10, 0xd5, 0x19, 0xd3, 0x31, 0xf9, 0xc4, 0x00, 0xaa, 0xe1, 0xe5, 0x0d, 0x48, 0x0c, 0xaa,
        0xe5, 0xa1, 0xc0, 0xfa, 0x99, 0xd7, 0x79, 0x24, 0xcf, 0x8d, 0xfe, 0x56, 0xcd, 0x70, 0x92,
        0xe7, 0xb9,
    ];

    if pk_bytes.len() != 1312 {
        return Err(LatticeArcError::ValidationError {
            message: format!("ML-DSA-44 KAT: pk size {} ≠ 1312", pk_bytes.len()),
        });
    }
    if sk_bytes.len() != 2560 {
        return Err(LatticeArcError::ValidationError {
            message: format!("ML-DSA-44 KAT: sk size {} ≠ 2560", sk_bytes.len()),
        });
    }
    if !bool::from(pk_bytes[..32].ct_eq(&PK_HEAD)) || !bool::from(pk_bytes[1280..].ct_eq(&PK_TAIL))
    {
        return Err(LatticeArcError::ValidationError {
            message: "ML-DSA-44 KAT: pk does not match ACVP vector tcId=1".to_string(),
        });
    }
    if !bool::from(sk_bytes[..32].ct_eq(&SK_HEAD)) || !bool::from(sk_bytes[2528..].ct_eq(&SK_TAIL))
    {
        return Err(LatticeArcError::ValidationError {
            message: "ML-DSA-44 KAT: sk does not match ACVP vector tcId=1".to_string(),
        });
    }

    // Sign/verify roundtrip on a fresh keypair (the ACVP-keyed sk
    // contains randomness state that the wrapper API doesn't expose;
    // re-keying through the public wrapper exercises the full
    // production path).
    const TEST_MESSAGE: &[u8] = b"FIPS 140-3 ML-DSA Known Answer Test";
    const CONTEXT: &[u8] = b"";
    let (public_key, secret_key) = generate_keypair(MlDsaParameterSet::MlDsa44).map_err(|e| {
        LatticeArcError::ValidationError {
            message: format!("ML-DSA roundtrip: key generation failed: {e}"),
        }
    })?;
    let signature =
        secret_key.sign(TEST_MESSAGE, CONTEXT).map_err(|e| LatticeArcError::ValidationError {
            message: format!("ML-DSA roundtrip: signing failed: {e}"),
        })?;
    let is_valid = public_key.verify(TEST_MESSAGE, &signature, CONTEXT).map_err(|e| {
        LatticeArcError::ValidationError {
            message: format!("ML-DSA roundtrip: verification failed: {e}"),
        }
    })?;
    if !is_valid {
        return Err(LatticeArcError::ValidationError {
            message: "ML-DSA roundtrip: valid signature was rejected".to_string(),
        });
    }
    const WRONG_MESSAGE: &[u8] = b"FIPS 140-3 ML-DSA Wrong Message";
    let is_valid_wrong = public_key.verify(WRONG_MESSAGE, &signature, CONTEXT).map_err(|e| {
        LatticeArcError::ValidationError {
            message: format!("ML-DSA roundtrip: verification check failed: {e}"),
        }
    })?;
    if is_valid_wrong {
        return Err(LatticeArcError::ValidationError {
            message: "ML-DSA roundtrip: invalid signature was accepted".to_string(),
        });
    }

    Ok(())
}

/// SLH-DSA-SHAKE-192s Known Answer Test (FIPS 205).
///
/// Drives the upstream `fips205` crate's `try_keygen_with_rng` with a
/// deterministic RNG pre-loaded with the NIST ACVP `keyGen` vector
/// `tcId=21` (parameter set `SLH-DSA-SHAKE-192s`), then asserts that
/// the produced `(pk, sk)` byte-exactly matches the ACVP-attested
/// expected output. This satisfies FIPS 140-3 §10.3.1's requirement
/// that power-up KATs use externally-attested fixed (input, output)
/// tuples.
///
/// Vector source:
/// <https://github.com/usnistgov/ACVP-Server/blob/master/gen-val/json-files/SLH-DSA-keyGen-FIPS205/internalProjection.json>
/// (mirrored in-tree by the upstream `fips205` crate).
///
/// SHAKE-192s rather than SHAKE-128s because the latter is not in the
/// fips205 crate's bundled ACVP vectors as of v0.4.1; both share the
/// same SHAKE-based code paths so coverage is equivalent.
///
/// A sign/verify roundtrip on a fresh wrapper-API keypair (SHAKE-128s,
/// the production default) is then run for additional coverage.
///
/// SLH-DSA (FIPS 205) has significantly longer execution times due to the
/// hash-based signature scheme. This check should be run as a conditional
/// self-test rather than at power-up.
///
/// # Errors
///
/// Returns error if keygen output does not match the ACVP vector, or if
/// the sign/verify roundtrip on the production-default key fails.
pub fn kat_slh_dsa() -> Result<()> {
    use crate::primitives::sig::slh_dsa::{SigningKey, SlhDsaSecurityLevel};
    use fips205::slh_dsa_shake_192s;
    use fips205::traits::{KeyGen, SerDes};

    // ACVP SLH-DSA-keyGen-FIPS205, parameter set SLH-DSA-SHAKE-192s, tcId = 21.
    // RNG fill order: sk_seed, sk_prf, pk_seed → push reverse.
    const SK_SEED: [u8; 24] = [
        0xbc, 0x95, 0x43, 0xf9, 0x1d, 0x3e, 0x83, 0xdf, 0x79, 0x3a, 0xcc, 0x0b, 0xbc, 0xdf, 0x54,
        0x81, 0x06, 0x91, 0xc7, 0x70, 0xf2, 0xdc, 0x5d, 0xad,
    ];
    const SK_PRF: [u8; 24] = [
        0x3a, 0xcf, 0xa7, 0x97, 0x32, 0xcd, 0xb7, 0x1d, 0x4e, 0xf1, 0xe9, 0xb2, 0xec, 0xa1, 0xa4,
        0x90, 0xf9, 0x77, 0xcb, 0x0c, 0xce, 0x3a, 0xaa, 0xc5,
    ];
    const PK_SEED: [u8; 24] = [
        0xf6, 0xc6, 0x4e, 0x2b, 0x66, 0x2b, 0xe5, 0xdd, 0xb6, 0xf9, 0xc2, 0x8c, 0xc6, 0x2c, 0x20,
        0xc7, 0x69, 0x7e, 0xfe, 0xda, 0xab, 0x1c, 0x90, 0x28,
    ];
    const PK_EXPECTED: [u8; 48] = [
        0xf6, 0xc6, 0x4e, 0x2b, 0x66, 0x2b, 0xe5, 0xdd, 0xb6, 0xf9, 0xc2, 0x8c, 0xc6, 0x2c, 0x20,
        0xc7, 0x69, 0x7e, 0xfe, 0xda, 0xab, 0x1c, 0x90, 0x28, 0xac, 0x30, 0xc2, 0x49, 0xf7, 0x5b,
        0x8b, 0x7f, 0x44, 0x73, 0x0e, 0x53, 0x41, 0x69, 0x88, 0x53, 0xb3, 0xf4, 0x8b, 0x5d, 0x15,
        0x0c, 0x80, 0x2e,
    ];
    const SK_EXPECTED: [u8; 96] = [
        0xbc, 0x95, 0x43, 0xf9, 0x1d, 0x3e, 0x83, 0xdf, 0x79, 0x3a, 0xcc, 0x0b, 0xbc, 0xdf, 0x54,
        0x81, 0x06, 0x91, 0xc7, 0x70, 0xf2, 0xdc, 0x5d, 0xad, 0x3a, 0xcf, 0xa7, 0x97, 0x32, 0xcd,
        0xb7, 0x1d, 0x4e, 0xf1, 0xe9, 0xb2, 0xec, 0xa1, 0xa4, 0x90, 0xf9, 0x77, 0xcb, 0x0c, 0xce,
        0x3a, 0xaa, 0xc5, 0xf6, 0xc6, 0x4e, 0x2b, 0x66, 0x2b, 0xe5, 0xdd, 0xb6, 0xf9, 0xc2, 0x8c,
        0xc6, 0x2c, 0x20, 0xc7, 0x69, 0x7e, 0xfe, 0xda, 0xab, 0x1c, 0x90, 0x28, 0xac, 0x30, 0xc2,
        0x49, 0xf7, 0x5b, 0x8b, 0x7f, 0x44, 0x73, 0x0e, 0x53, 0x41, 0x69, 0x88, 0x53, 0xb3, 0xf4,
        0x8b, 0x5d, 0x15, 0x0c, 0x80, 0x2e,
    ];

    let mut rng = FixedBytesRng::new();
    rng.push(&PK_SEED);
    rng.push(&SK_PRF);
    rng.push(&SK_SEED);

    let (pk_act, sk_act) = slh_dsa_shake_192s::KG::try_keygen_with_rng(&mut rng).map_err(|e| {
        LatticeArcError::ValidationError {
            message: format!("SLH-DSA-SHAKE-192s KAT: deterministic keygen failed: {e}"),
        }
    })?;
    let pk_bytes = pk_act.into_bytes();
    let sk_bytes = sk_act.into_bytes();

    if !bool::from(pk_bytes.ct_eq(&PK_EXPECTED)) {
        return Err(LatticeArcError::ValidationError {
            message: "SLH-DSA-SHAKE-192s KAT: pk does not match ACVP vector tcId=21".to_string(),
        });
    }
    if !bool::from(sk_bytes.ct_eq(&SK_EXPECTED)) {
        return Err(LatticeArcError::ValidationError {
            message: "SLH-DSA-SHAKE-192s KAT: sk does not match ACVP vector tcId=21".to_string(),
        });
    }

    // Sign/verify roundtrip on the production-default SHAKE-128s key
    // (the wrapper API's default). Catches sign+verify path bugs that
    // a pure keygen KAT cannot reach.
    const TEST_MESSAGE: &[u8] = b"FIPS 140-3 SLH-DSA Known Answer Test";
    let (signing_key, verifying_key) = SigningKey::generate(SlhDsaSecurityLevel::Shake128s)
        .map_err(|e| LatticeArcError::ValidationError {
            message: format!("SLH-DSA roundtrip: key generation failed: {e}"),
        })?;
    let signature =
        signing_key.sign(TEST_MESSAGE, &[]).map_err(|e| LatticeArcError::ValidationError {
            message: format!("SLH-DSA roundtrip: signing failed: {e}"),
        })?;
    let is_valid = verifying_key.verify(TEST_MESSAGE, &signature, &[]).map_err(|e| {
        LatticeArcError::ValidationError {
            message: format!("SLH-DSA roundtrip: verification failed: {e}"),
        }
    })?;
    if !is_valid {
        return Err(LatticeArcError::ValidationError {
            message: "SLH-DSA roundtrip: valid signature was rejected".to_string(),
        });
    }
    const WRONG_MESSAGE: &[u8] = b"FIPS 140-3 SLH-DSA Wrong Message";
    let is_valid_wrong = verifying_key.verify(WRONG_MESSAGE, &signature, &[]).map_err(|e| {
        LatticeArcError::ValidationError {
            message: format!("SLH-DSA roundtrip: verification check failed: {e}"),
        }
    })?;
    if is_valid_wrong {
        return Err(LatticeArcError::ValidationError {
            message: "SLH-DSA roundtrip: invalid signature was accepted".to_string(),
        });
    }

    Ok(())
}

/// FN-DSA Known Answer Test (draft FIPS 206)
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
/// FN-DSA (draft FIPS 206) requires a larger stack size for key generation.
/// This test should be run as a conditional self-test rather than at power-up.
///
/// # Errors
///
/// Returns error if key generation, signing, or verification fails.
pub fn kat_fn_dsa() -> Result<()> {
    use crate::primitives::sig::fndsa::{FnDsaSecurityLevel, KeyPair};
    // `fn-dsa 0.3` requires `rand_core 0.6` traits — see workspace
    // `rand_core_0_6` dep for the bridge rationale.
    use rand_core_0_6::OsRng;

    // Fixed test message for KAT
    const TEST_MESSAGE: &[u8] = b"FIPS 140-3 FN-DSA Known Answer Test";

    // FN-DSA requires a larger stack size for key generation
    // Run the test in a separate thread with increased stack size
    std::thread::Builder::new()
        .stack_size(32 * 1024 * 1024) // 32 MB stack
        .spawn(|| -> Result<()> {
            // Generate a keypair using FN-DSA-512 (Level I security)
            let mut rng = OsRng;
            let mut keypair = KeyPair::generate_with_rng(&mut rng, FnDsaSecurityLevel::Level512)
                .map_err(|e| LatticeArcError::ValidationError {
                    message: format!("FN-DSA KAT: key generation failed: {}", e),
                })?;

            // Verify key sizes match expected values
            let expected_pk_size = FnDsaSecurityLevel::Level512.verifying_key_size();
            if keypair.verifying_key().to_bytes().len() != expected_pk_size {
                return Err(LatticeArcError::ValidationError {
                    message: format!(
                        "FN-DSA KAT: verifying key size mismatch: expected {}, got {}",
                        expected_pk_size,
                        keypair.verifying_key().to_bytes().len()
                    ),
                });
            }

            let expected_sk_size = FnDsaSecurityLevel::Level512.signing_key_size();
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
            let mut rng = OsRng;
            let signature = keypair.sign_with_rng(&mut rng, TEST_MESSAGE).map_err(|e| {
                LatticeArcError::ValidationError {
                    message: format!("FN-DSA KAT: signing failed: {}", e),
                }
            })?;

            // Verify signature size
            let expected_sig_size = FnDsaSecurityLevel::Level512.signature_size();
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

/// Heuristic: does the file at `path` look like a LatticeArc artifact?
///
/// `current_exe()` returns the path to the running executable; when
/// LatticeArc is loaded as a dynamic library by a host (Python, Node,
/// JVM, etc.) that path is the host interpreter, not the library. This
/// helper recognises three kinds of legitimate LatticeArc-on-disk
/// artifacts:
///   * the platform-specific shared library (`liblatticearc.so` /
///     `liblatticearc.dylib` / `latticearc.dll`)
///   * the LatticeArc CLI binary (`latticearc-cli` / `latticearc-cli.exe`)
///   * any other binary whose file name contains `latticearc` (covers
///     statically-linked downstream binaries that have re-exported the
///     name into their own image).
///
/// Anything else is treated as an unverifiable host process and the
/// integrity test refuses to HMAC it.
fn path_looks_like_latticearc_module(path: &std::path::Path) -> bool {
    let Some(file_name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    let lower = file_name.to_ascii_lowercase();
    // tightened from a permissive
    // `starts_with("latticearc")` plus a blanket `target/deps/` accept
    // to (a) an exact list of names produced by this build, plus
    // (b) cargo-test binary recognition via the `<crate-name>-<16-hex>`
    // suffix shape inside `target/{debug,release}/deps/`. Previously
    // a binary named `latticearc-evil-host` would have been HMAC-
    // checked against the EXPECTED_HMAC, surfacing as "module
    // integrity OK" for a non-LatticeArc image.
    //
    // Note: the cargo-deps shape check intentionally does NOT require
    // a `latticearc` crate-name prefix — integration tests under
    // `latticearc/tests/`, `tests/tests/`, and other workspace
    // members produce binaries whose crate name reflects the test
    // file (e.g. `primitives_self_test_conditional_kats-<hex>`),
    // none of which start with `latticearc`. They all statically
    // link the latticearc crate and are legitimate consumers, so
    // the integrity test must accept them. The 16-hex-suffix shape
    // is what excludes adversary binaries: a hand-crafted binary
    // dropped into `deps/` to fake the integrity check would either
    // (i) lack the 16-hex suffix (cargo always generates one) or
    // (ii) be a real cargo-test binary, in which case the question
    // reduces to "does the developer trust their own `target/`",
    // which the workspace already assumes.
    let exact_names = [
        "liblatticearc.so",
        "liblatticearc.dylib",
        "latticearc.dll",
        "latticearc-cli",
        "latticearc-cli.exe",
    ];
    if exact_names.iter().any(|n| lower == *n) {
        return true;
    }
    // Accept any cargo-test binary under a `…/target/**/deps/` path
    // (no hardcoded profile name, but bounded nesting depth). An exact
    // `target/<profile>/deps/` allowlist would reject:
    //   * custom profiles (`[profile.valgrind]`, `[profile.release-validation]`)
    //   * `cargo llvm-cov`'s nested `target/llvm-cov-target/release/deps/`
    //   * any future tool that scopes its target dir under `target/`
    // — and the resulting `path_looks_like` rejection would fail the
    // integrity test, abort the FIPS POST, and SIGABRT the process.
    //
    // Security note: walking the parent chain for `target` is safe
    // even at this fuzzier shape because the integrity-test threat
    // model rejects adversary-injected binaries by HMAC mismatch, not
    // by path. The profile-name and any tool-specific nesting are
    // just where the build system chose to put the artifact; an
    // attacker who can write into `target/<arbitrary>/../deps/` can
    // already write into `target/release/deps/` too.
    //
    // Hop bound: the deepest known cargo-tooling layout is
    // `target/llvm-cov-target/<profile>/deps/binary` — exactly 3 hops
    // from `deps`'s parent (`<profile>` → `llvm-cov-target` → `target`).
    // The plain `target/<profile>/deps/binary` shape is 2 hops. Bound
    // at 3 hops: covers every known cargo, llvm-cov, and custom-
    // profile layout while rejecting deeper Bazel-style or pathological
    // CI paths like `/builds/foo/target/cache/x/y/deps/`.
    let parent_ok = path.parent().and_then(|p| {
        if p.file_name().and_then(|n| n.to_str()) != Some("deps") {
            return None;
        }
        p.ancestors()
            .skip(1)
            .take(3)
            .any(|a| a.file_name().and_then(|n| n.to_str()) == Some("target"))
            .then_some(())
    });
    if parent_ok.is_some() {
        // Strip `.exe` if present, then split on the LAST `-` to get
        // crate-name vs hex-suffix. Accept any 16-hex-suffix file in
        // `target/{debug,release}/deps/` — see the comment above for
        // why the crate-name prefix is not constrained further.
        let stem = lower.strip_suffix(".exe").unwrap_or(&lower);
        if let Some((_crate_name, suffix)) = stem.rsplit_once('-')
            && suffix.len() == 16
            && suffix.chars().all(|c| c.is_ascii_hexdigit())
        {
            return true;
        }
    }
    false
}

/// Software/Firmware Integrity Test
///
/// FIPS 140-3 Software/Firmware Load Test (Section 9.2.2).
///
/// Verifies the integrity of the cryptographic module at power-up by
/// computing an HMAC-SHA256 digest of the on-disk module artifact and
/// comparing it against the build-time-recorded expected value.
///
/// # Module location
///
/// The module path is resolved via `std::env::current_exe()` and then
/// cross-checked with [`path_looks_like_latticearc_module`]. If the
/// resolved path does not look like a LatticeArc shared library or
/// LatticeArc-bearing binary (e.g. when the library is loaded by a
/// host interpreter and `current_exe()` returns the interpreter
/// itself), the test returns an explicit "cannot locate" error rather
/// than HMACing the wrong file. Without `unsafe`, which the workspace
/// `unsafe_code` lint forbids, there is no portable way to call the
/// platform dynamic-loader APIs (`dladdr`, `dl_iterate_phdr`,
/// `GetModuleFileName`) that would recover the library's path
/// directly; the dynamic-load case must be handled by the deployment
/// (e.g. by also shipping a static-link CLI that runs the integrity
/// test out-of-band).
///
/// # Errors
///
/// Returns error if:
/// - `current_exe()` is unavailable
/// - The resolved path does not look like a LatticeArc artifact
/// - The artifact cannot be read
/// - HMAC computation fails
/// - The computed HMAC does not match the build-time expected value
pub fn integrity_test() -> Result<()> {
    // FIPS requires using a cryptographic key for HMAC
    // For a self-contained integrity test, we use a deterministic key derived
    // from the module identity. In production FIPS, this would come from HSM/TPM.
    const INTEGRITY_KEY: &[u8] = crate::types::domains::MODULE_INTEGRITY_HMAC_KEY;

    // Locate the latticearc module binary on disk.
    //
    // `std::env::current_exe()` returns the path to the *host* binary,
    // which is correct only when latticearc is statically linked into
    // that binary. When latticearc is loaded as a `.so`/`.dylib`/`.dll`
    // (e.g. from a Python or Node.js extension), `current_exe()` points
    // at the host interpreter, and HMACing it would silently verify
    // the wrong file.
    //
    // Without `unsafe` (forbidden crate-wide) we cannot call
    // platform dynamic-loader APIs (`dladdr`, `dl_iterate_phdr`,
    // `GetModuleFileName`) to recover the library's own path. Instead
    // we read `current_exe()`, then check whether the resolved file
    // name matches one of the LatticeArc artifact names compiled
    // into this build (`liblatticearc.so`, `liblatticearc.dylib`,
    // `latticearc.dll`, or any binary that links them statically).
    // If the path looks like a host-process executable rather than the
    // LatticeArc library, return an explicit "cannot locate" error so
    // FIPS callers see the integrity gap rather than a silent
    // false-positive verification of the wrong file.
    let module_path = std::env::current_exe().map_err(|e| LatticeArcError::ValidationError {
        message: format!("Integrity test: cannot locate module binary: {}", e),
    })?;

    if !path_looks_like_latticearc_module(&module_path) {
        return Err(LatticeArcError::ValidationError {
            message: format!(
                "Integrity test: current_exe() = {:?} does not appear to be a \
                 LatticeArc library or a binary that statically links it. \
                 This build cannot verify dynamic-library integrity without \
                 platform dynamic-loader APIs (forbidden by the workspace \
                 `unsafe_code` lint). Run the integrity test from a binary \
                 that statically links latticearc, or supply an external \
                 library path via the FIPS deployment manifest.",
                module_path,
            ),
        });
    }

    // Read the module binary
    let module_bytes =
        std::fs::read(&module_path).map_err(|e| LatticeArcError::ValidationError {
            message: format!("Integrity test: cannot read module binary: {}", e),
        })?;

    // Compute HMAC-SHA256 over the module binary via the primitives wrapper
    // (FIPS-validated aws-lc-rs backend).
    let computed_hmac = crate::primitives::mac::hmac::hmac_sha256(INTEGRITY_KEY, &module_bytes)
        .map_err(|e| LatticeArcError::ValidationError {
            message: format!("Integrity test: HMAC computation failed: {}", e),
        })?;

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
            #[expect(clippy::print_stderr, reason = "Development mode diagnostic output")]
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
#[non_exhaustive]
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
/// use latticearc::primitives::self_test::{set_module_error, ModuleErrorCode};
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
/// use latticearc::primitives::self_test::is_module_operational;
///
/// if !is_module_operational() {
///     eprintln!("Module is not operational - crypto operations blocked");
/// }
/// ```
#[must_use]
pub fn is_module_operational() -> bool {
    // M1: use SeqCst loads to match the SeqCst stores in
    // `set_module_error`. Acquire-only loads synchronize with each
    // location's own Release store but do NOT preserve a single
    // total order across MODULE_ERROR_CODE and SELF_TEST_PASSED;
    // on weakly-ordered architectures (ARM, POWER) an observer
    // could see one flag's update before the other's, which for a
    // FIPS 140-3 §9.6 module-state gate is auditor-visible. SeqCst
    // on both sides ensures a total observation order.
    let error_code = ModuleErrorCode::from_u32(MODULE_ERROR_CODE.load(Ordering::SeqCst));
    !error_code.is_error() && SELF_TEST_PASSED.load(Ordering::SeqCst)
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
/// Reset FIPS module error state (**testing only**).
///
/// FIPS 140-3 §9.6 requires full module re-initialization (re-running POST)
/// to recover from error state. This function bypasses that contract and
/// is intended solely for test isolation in negative-path tests that
/// deliberately trip `set_module_error`.
///
/// the previous `pub` + `#[doc(hidden)]`
/// shape was reachable from any downstream crate and let an external
/// caller silently restore "operational" without re-validating. Now
/// gated behind `#[cfg(any(test, feature = "test-utils"))]` so:
///   * `cargo test` builds inside this crate see it (in-tree tests)
///   * downstream crates that opt into `test-utils` see it (the
///     `latticearc-tests` integration crate enables this feature)
///   * production builds (no `test-utils`) get no exposed symbol at all
#[cfg(any(test, feature = "test-utils"))]
#[doc(hidden)]
pub fn clear_error_state() {
    MODULE_ERROR_CODE.store(ModuleErrorCode::NoError as u32, Ordering::SeqCst);
    MODULE_ERROR_TIMESTAMP.store(0, Ordering::SeqCst);
    // SeqCst (not Release) so this store participates in the same total
    // order as the SeqCst loads in `is_module_operational`/`self_tests_passed`.
    SELF_TEST_PASSED.store(false, Ordering::SeqCst);
}

/// Clear error state and restore module to operational (**testing only**).
///
/// Use this in negative tests (e.g., PCT failure tests) that intentionally trigger
/// `set_module_error` but need to avoid poisoning the global state for other
/// tests running in the same process. Unlike `clear_error_state`, this restores
/// `SELF_TEST_PASSED` to `true` so the module remains operational.
///
/// same gating as `clear_error_state` above —
/// FIPS 140-3 §9.6 forbids external recovery from error state without re-
/// running POST.
#[cfg(any(test, feature = "test-utils"))]
#[doc(hidden)]
pub fn restore_operational_state() {
    MODULE_ERROR_CODE.store(ModuleErrorCode::NoError as u32, Ordering::SeqCst);
    MODULE_ERROR_TIMESTAMP.store(0, Ordering::SeqCst);
    // SeqCst (not Release) so this store participates in the same total
    // order as the SeqCst loads in `is_module_operational`/`self_tests_passed`.
    SELF_TEST_PASSED.store(true, Ordering::SeqCst);
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
    // SeqCst matches `is_module_operational` so both public FIPS gate
    // accessors observe writers in the same total order.
    SELF_TEST_PASSED.load(Ordering::SeqCst)
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
        SELF_TEST_PASSED.store(true, Ordering::SeqCst);
    } else {
        // FIPS 140-3 §9.1: Self-test failure requires module abort.
        // Set error state first so any concurrent readers see a definitive error.
        set_module_error(ModuleErrorCode::SelfTestFailure);
        // FIPS 140-3 §9.1 requires immediate abort on self-test failure.
        // No logging after this point — abort is non-recoverable.
        std::process::abort();
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
#[expect(
    clippy::indexing_slicing,
    reason = "indexing into a slice whose length is known at this site"
)]
mod tests {
    use super::*;

    /// RAII guard that restores `SELF_TEST_PASSED = true` and clears
    /// the module error state when dropped. Tests that deliberately
    /// set the FIPS module to an error state to exercise blocking
    /// behaviour MUST instantiate this at the top of the test body
    /// so that — even on panic — the global state is restored before
    /// the next test (which may run in parallel and depend on
    /// `is_module_operational()` returning true) starts. Without
    /// this, a parallel runner schedules a state-reading test
    /// during the brief window where SELF_TEST_PASSED is false and
    /// it (correctly) reports the module as non-operational, then
    /// fails its own assertion.
    ///
    /// `serial_test`-style serialisation is strictly worse here: it
    /// widens the false-state window from "during this test only" to
    /// "during this test AND every concurrent reader the queue blocks
    /// on", cascading the failure into hundreds of unrelated tests.
    /// The guard pattern keeps the window scoped to the test body.
    ///
    /// `_not_send_or_sync: PhantomData<*mut ()>` makes the guard
    /// neither `Send` nor `Sync` at compile time (raw pointers are
    /// neither). Without it, a zero-size struct is implicitly
    /// `Send + Sync`, so a test that accidentally moves the guard
    /// into a `thread::spawn(..)` closure would restore the FIPS
    /// state on the spawned thread's drop — racing with the main
    /// test body and re-opening exactly the false-state-leak we are
    /// guarding against. The marker raises that to a compile error.
    struct FipsStateGuard {
        _not_send_or_sync: core::marker::PhantomData<*mut ()>,
    }
    impl FipsStateGuard {
        const fn new() -> Self {
            Self { _not_send_or_sync: core::marker::PhantomData }
        }
    }
    impl Drop for FipsStateGuard {
        fn drop(&mut self) {
            // `restore_operational_state` is the canonical "bring
            // the module back to operational" entry point used by
            // the `clear_error_state` doc-tests. It sets
            // SELF_TEST_PASSED = true (SeqCst) and clears the error
            // code + timestamp.
            restore_operational_state();
        }
    }

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
    fn test_ml_kem_768_roundtrip_passes() {
        assert!(roundtrip_ml_kem_768().is_ok());
    }

    #[test]
    fn test_power_up_tests_pass_succeeds() {
        let result = run_power_up_tests();
        assert!(result.is_pass(), "Power-up tests should pass: {:?}", result);
    }

    #[test]
    fn test_power_up_tests_with_report_succeeds() {
        let report = run_power_up_tests_with_report();
        assert!(report.overall_result.is_pass(), "Overall result should pass");
        assert!(!report.tests.is_empty(), "Should have individual test results");

        for test in &report.tests {
            assert!(test.result.is_pass(), "Test {} should pass", test.algorithm);
            assert!(test.duration_us.is_some(), "Duration should be measured");
        }
    }

    // Lock the accepted/rejected path shapes so a future refactor
    // can't re-narrow the allowlist. Re-narrowing produces a
    // `process::abort` at FIPS POST when run from a legitimate
    // cargo-test artifact path that the allowlist no longer
    // recognises (custom profile, nested tool target dir, etc.).
    #[test]
    fn test_path_looks_like_latticearc_module_accepts_known_shapes() {
        use std::path::PathBuf;

        // Exact-name binaries (CLI / dynamic library names).
        for name in [
            "liblatticearc.so",
            "liblatticearc.dylib",
            "latticearc.dll",
            "latticearc-cli",
            "latticearc-cli.exe",
        ] {
            assert!(
                path_looks_like_latticearc_module(&PathBuf::from(name)),
                "exact-name binary should be accepted: {name}"
            );
        }

        // Cargo-test deps shapes within the bounded ancestor walk.
        // Layouts at depth >3 (more than `target/../<profile>/deps/`)
        // are intentionally NOT accepted — see the rejection test below.
        for path in [
            // Standard `target/<profile>/deps/` (2 hops to target).
            "/work/repo/target/release/deps/latticearc-0123456789abcdef",
            "/work/repo/target/debug/deps/audit_regression_signatures-fedcba9876543210",
            // Custom profile (e.g. `[profile.valgrind]`) — still 2 hops.
            "/work/repo/target/valgrind/deps/latticearc-0123456789abcdef",
            // `cargo llvm-cov` nested target dir — 3 hops (the deepest
            // known legitimate cargo-tooling layout).
            "/work/repo/target/llvm-cov-target/release/deps/latticearc-0123456789abcdef",
        ] {
            assert!(
                path_looks_like_latticearc_module(&PathBuf::from(path)),
                "cargo-test deps shape should be accepted: {path}"
            );
        }
    }

    #[test]
    fn test_path_looks_like_latticearc_module_rejects_adversarial_shapes() {
        use std::path::PathBuf;

        for path in [
            // Wrong hex-suffix length (15 vs required 16).
            "/work/repo/target/release/deps/latticearc-0123456789abcde",
            // Suffix is not hex.
            "/work/repo/target/release/deps/latticearc-evil-not-hex-here",
            // No `deps` parent.
            "/work/repo/target/release/latticearc-0123456789abcdef",
            // Not under any `target` ancestor — host interpreter case.
            "/usr/bin/python3.12",
            "/opt/node/bin/node",
            // Depth >3 from `deps` to `target`. Beyond the deepest
            // known cargo-tooling layout (`target/llvm-cov-target/
            // <profile>/deps/`); accepting this opens the trust scope
            // to Bazel-style or pathological CI paths like
            // `/builds/foo/target/cache/x/y/deps/`.
            "/work/repo/target/some-tool/release/instrumented/deps/foo-0123456789abcdef",
        ] {
            assert!(
                !path_looks_like_latticearc_module(&PathBuf::from(path)),
                "non-LatticeArc path should be rejected: {path}"
            );
        }
    }

    #[test]
    fn test_self_test_result_methods_return_correct_values_succeeds() {
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
    fn test_initialize_and_verify_sets_passed_flag_succeeds() {
        let _guard = FipsStateGuard::new();
        // Reset state for test
        SELF_TEST_PASSED.store(false, Ordering::SeqCst);

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
        assert!(result.is_ok(), "ML-DSA-44 KAT should pass: {:?}", result);
    }

    #[test]
    fn test_slh_dsa_kat_passes() {
        let result = kat_slh_dsa();
        assert!(result.is_ok(), "SLH-DSA-SHAKE-192s KAT should pass: {:?}", result);
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
    fn test_module_error_code_from_u32_fails() {
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
    fn test_module_error_code_is_error_fails() {
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
    fn test_module_error_code_description_returns_correct_strings_fails() {
        assert_eq!(ModuleErrorCode::NoError.description(), "No error");
        assert_eq!(ModuleErrorCode::SelfTestFailure.description(), "FIPS 140-3 self-test failure");
        assert_eq!(ModuleErrorCode::EntropyFailure.description(), "Entropy source failure");
    }

    #[test]
    fn test_set_and_get_module_error_succeeds() {
        let _guard = FipsStateGuard::new();
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
    fn test_is_module_operational_succeeds() {
        let _guard = FipsStateGuard::new();
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
    fn test_verify_operational_with_error_state_fails() {
        let _guard = FipsStateGuard::new();
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
    fn test_set_error_clears_self_test_passed_fails() {
        let _guard = FipsStateGuard::new();
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
    fn test_module_error_state_struct_is_correct() {
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
    fn test_module_error_code_all_descriptions_return_correct_strings_fails() {
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
    fn test_set_module_error_no_error_does_not_clear_self_test_fails() {
        let _guard = FipsStateGuard::new();
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
    fn test_self_test_result_debug_clone_work_correctly_succeeds() {
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
    fn test_individual_test_result_fields_succeeds() {
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
    fn test_self_test_report_fields_succeeds() {
        let report = run_power_up_tests_with_report();
        assert_eq!(report.tests.len(), 9); // SHA-256, HKDF, AES-GCM, SHA3-256, HMAC, ML-KEM, ML-DSA, SLH-DSA, FN-DSA
        assert!(report.total_duration_us > 0);

        let cloned = report.clone();
        assert_eq!(cloned.tests.len(), 9);

        let debug = format!("{:?}", report);
        assert!(debug.contains("SelfTestReport"));
    }

    #[test]
    fn test_module_error_code_debug_produces_expected_output_fails() {
        let code = ModuleErrorCode::SelfTestFailure;
        let debug = format!("{:?}", code);
        assert!(debug.contains("SelfTestFailure"));

        let cloned = code;
        assert_eq!(cloned, ModuleErrorCode::SelfTestFailure);
    }

    #[test]
    fn test_module_error_state_debug_clone_work_correctly_fails() {
        let state =
            ModuleErrorState { error_code: ModuleErrorCode::EntropyFailure, timestamp: 1000 };
        let cloned = state.clone();
        assert_eq!(cloned.error_code, ModuleErrorCode::EntropyFailure);
        assert_eq!(cloned.timestamp, 1000);

        let debug = format!("{:?}", state);
        assert!(debug.contains("EntropyFailure"));
    }

    #[test]
    fn test_verify_operational_without_self_tests_fails() {
        let _guard = FipsStateGuard::new();
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
    fn test_multiple_error_states_in_sequence_fails() {
        let _guard = FipsStateGuard::new();
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
    fn test_self_test_result_fail_to_result_contains_message_fails() {
        let fail = SelfTestResult::Fail("module corrupted".to_string());
        let result = fail.to_result();
        assert!(result.is_err());
        if let Err(LatticeArcError::ValidationError { message }) = result {
            assert!(message.contains("module corrupted"));
            assert!(message.contains("FIPS 140-3"));
        }
    }

    #[test]
    fn test_individual_test_result_with_no_duration_succeeds() {
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
    fn test_self_test_report_with_failures_has_correct_fields_fails() {
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
    fn test_module_error_code_repr_values_fails() {
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
    fn test_module_error_code_from_u32_boundary_fails() {
        // Values 8-254 all map to UnknownCriticalError
        assert_eq!(ModuleErrorCode::from_u32(8), ModuleErrorCode::UnknownCriticalError);
        assert_eq!(ModuleErrorCode::from_u32(128), ModuleErrorCode::UnknownCriticalError);
        assert_eq!(ModuleErrorCode::from_u32(254), ModuleErrorCode::UnknownCriticalError);
        assert_eq!(ModuleErrorCode::from_u32(u32::MAX), ModuleErrorCode::UnknownCriticalError);
    }

    #[test]
    fn test_module_error_state_no_error_timestamp_zero_fails() {
        let _guard = FipsStateGuard::new();
        clear_error_state();
        let state = get_module_error_state();
        assert!(!state.is_error());
        assert_eq!(state.timestamp, 0);
    }

    #[test]
    fn test_module_error_state_error_has_nonzero_timestamp_fails() {
        let _guard = FipsStateGuard::new();
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
    fn test_verify_operational_error_message_contains_description_fails() {
        let _guard = FipsStateGuard::new();
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
    fn test_all_error_codes_block_operations_fails() {
        let _guard = FipsStateGuard::new();
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

        // Cleanup. Do NOT call `initialize_and_test()` here:
        // `initialize_and_test` runs the full power-up KAT suite and
        // calls `process::abort()` if any KAT fails. Under Valgrind
        // (CI's Memory Safety Checks job) the KATs run slow enough
        // that occasional timing-sensitive failures abort the test
        // runner — exit 134 SIGABRT, masking all other test results.
        // Just clear the error and re-arm the SELF_TEST_PASSED flag;
        // the next test that needs a fresh power-up will run it.
        clear_error_state();
        SELF_TEST_PASSED.store(true, Ordering::SeqCst);
    }

    #[test]
    fn test_initialize_and_test_sets_flag_succeeds() {
        let _guard = FipsStateGuard::new();
        SELF_TEST_PASSED.store(false, Ordering::SeqCst);
        clear_error_state();
        assert!(!self_tests_passed());

        let result = initialize_and_test();
        assert!(result.is_pass());
        assert!(self_tests_passed());
    }

    #[test]
    fn test_current_timestamp_reasonable_succeeds() {
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
    fn test_roundtrip_ml_kem_768_always_succeeds() {
        // ML-KEM uses randomness but should always succeed
        for _ in 0..3 {
            assert!(roundtrip_ml_kem_768().is_ok());
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
    fn test_run_power_up_tests_with_report_all_pass_succeeds() {
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

    // ---- Coverage: direct KAT calls for SHA3-256 and HMAC-SHA256 ----

    #[test]
    fn test_kat_sha3_256_passes() {
        assert!(kat_sha3_256().is_ok());
    }

    #[test]
    fn test_kat_hmac_sha256_passes() {
        assert!(kat_hmac_sha256().is_ok());
    }

    #[test]
    fn test_self_test_report_all_fields_populated_succeeds() {
        let report = run_power_up_tests_with_report();
        assert!(report.overall_result.is_pass());
        // Verify we have the expected number of algorithm tests
        assert!(report.tests.len() >= 9, "Should have at least 9 KAT results");
        // Verify total duration is populated
        assert!(report.total_duration_us > 0);
        // Verify each test has algorithm name and timing
        for test in &report.tests {
            assert!(!test.algorithm.is_empty(), "Algorithm name should not be empty");
            assert!(
                test.duration_us.is_some(),
                "Duration should be measured for {}",
                test.algorithm
            );
        }
    }

    #[test]
    fn test_error_state_timestamp_ordering_fails() {
        let _guard = FipsStateGuard::new();
        clear_error_state();

        // Set first error
        set_module_error(ModuleErrorCode::EntropyFailure);
        let state1 = get_module_error_state();
        let ts1 = state1.timestamp;

        // Set second error (same second or later)
        set_module_error(ModuleErrorCode::IntegrityFailure);
        let state2 = get_module_error_state();
        let ts2 = state2.timestamp;

        // Timestamps should be non-decreasing
        assert!(ts2 >= ts1, "Second timestamp should be >= first");
        assert_eq!(state2.error_code, ModuleErrorCode::IntegrityFailure);

        // Cleanup
        clear_error_state();
    }

    #[test]
    fn test_verify_operational_after_reset_succeeds() {
        let _guard = FipsStateGuard::new();
        // Set error state
        set_module_error(ModuleErrorCode::HsmError);
        assert!(verify_operational().is_err());

        // Clear and re-initialize
        clear_error_state();
        let result = initialize_and_test();
        assert!(result.is_pass());
        assert!(verify_operational().is_ok());
        assert!(is_module_operational());
    }
}
