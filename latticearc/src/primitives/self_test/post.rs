#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

use crate::prelude::error::{LatticeArcError, Result};
use std::sync::atomic::Ordering;

use super::SELF_TEST_PASSED;
use super::error_state::{
    ModuleErrorCode, get_module_error_state, self_tests_passed, set_module_error,
};
use super::integrity::integrity_test;
use super::kat::{
    kat_aes_256_gcm, kat_fn_dsa, kat_hkdf_sha256, kat_hmac_sha256, kat_ml_dsa, kat_sha3_256,
    kat_sha256, kat_slh_dsa, roundtrip_ml_kem_768,
};
// Only referenced inside the `fips-strict-integrity` gate in
// `verify_operational` below; import under the same cfg so builds
// without that feature (or test/test-utils builds, which the gate
// excludes) don't trip `unused_imports`.
#[cfg(all(feature = "fips-strict-integrity", not(any(test, feature = "test-utils"))))]
use super::INTEGRITY_TEST_CONFIGURED;

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
                message: format!("FIPS 140-3 self-test failed: {msg}"),
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
        return SelfTestResult::Fail(format!("Module Integrity Test failed: {e}"));
    }

    // 1. SHA-256 KAT (foundational - other tests depend on hash)
    if let Err(e) = kat_sha256() {
        return SelfTestResult::Fail(format!("SHA-256 KAT failed: {e}"));
    }

    // 2. HKDF-SHA256 KAT (depends on HMAC-SHA256)
    if let Err(e) = kat_hkdf_sha256() {
        return SelfTestResult::Fail(format!("HKDF-SHA256 KAT failed: {e}"));
    }

    // 3. AES-256-GCM KAT
    if let Err(e) = kat_aes_256_gcm() {
        return SelfTestResult::Fail(format!("AES-256-GCM KAT failed: {e}"));
    }

    // 4. SHA3-256 KAT
    if let Err(e) = kat_sha3_256() {
        return SelfTestResult::Fail(format!("SHA3-256 KAT failed: {e}"));
    }

    // 5. HMAC-SHA256 KAT
    if let Err(e) = kat_hmac_sha256() {
        return SelfTestResult::Fail(format!("HMAC-SHA256 KAT failed: {e}"));
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
        return SelfTestResult::Fail(format!("ML-KEM-768 roundtrip failed: {e}"));
    }

    // 7. ML-DSA-44 KAT (ACVP keygen vector + sign/verify roundtrip).
    if let Err(e) = kat_ml_dsa() {
        return SelfTestResult::Fail(format!("ML-DSA-44 KAT failed: {e}"));
    }

    // 8. SLH-DSA-SHAKE-192s KAT (ACVP keygen vector + sign/verify roundtrip).
    if let Err(e) = kat_slh_dsa() {
        return SelfTestResult::Fail(format!("SLH-DSA-SHAKE-192s KAT failed: {e}"));
    }

    // 9. FN-DSA self-consistency (runs in separate thread with 32 MB stack).
    if let Err(e) = kat_fn_dsa() {
        return SelfTestResult::Fail(format!("FN-DSA roundtrip failed: {e}"));
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

/// Run power-up tests with detailed reporting.
///
/// Same sequence as [`run_power_up_tests`] — integrity test first per
/// FIPS 140-3 §9.2.2, then the KATs / self-consistency tests — but
/// returns a [`SelfTestReport`] capturing individual results and timings
/// for diagnostics. On Pass this sets `SELF_TEST_PASSED` so the module
/// becomes operational; on Fail it calls [`set_module_error`] so
/// subsequent crypto-op gates reject calls.
///
/// Unlike [`initialize_and_test`], this function does **not** abort the
/// process on failure — FIPS 140-3 §9.1's "immediate abort" requirement
/// is the caller's responsibility for this entry point. Inspect the
/// returned report and abort if your deployment needs strict §9.1
/// behaviour, or call [`initialize_and_test`] instead.
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

    // Module integrity test (FIPS 140-3 §9.2.2): MUST run first, before
    // any cryptographic operation. Same ordering as `run_power_up_tests`.
    // If the integrity test fails, §9.2.2 requires the module to inhibit
    // all subsequent crypto — we record a skip for each downstream KAT and
    // return early. The sibling `run_power_up_tests` already short-circuits
    // on integrity failure; the reporting variant previously continued
    // through eight more KATs on a binary that just failed tamper
    // detection, which is exactly the threat scenario this test exists for.
    let integrity_start = Instant::now();
    let integrity_outcome = integrity_test();
    let integrity_result = match &integrity_outcome {
        Ok(()) => SelfTestResult::Pass,
        Err(e) => {
            overall_pass = false;
            SelfTestResult::Fail(e.to_string())
        }
    };
    tests.push(IndividualTestResult {
        algorithm: "Module-Integrity".to_string(),
        result: integrity_result,
        duration_us: Some(duration_to_us(integrity_start.elapsed())),
    });
    if integrity_outcome.is_err() {
        // Set the FIPS module-error state so downstream `verify_operational`
        // calls reject too; mirror `run_power_up_tests`'s effect even though
        // this variant returns a Report rather than aborting.
        set_module_error(ModuleErrorCode::IntegrityFailure);
        // Record every downstream KAT as "not run" so report consumers see
        // exactly which tests were inhibited by the §9.2.2 halt. We don't
        // execute the underlying KAT functions — running tamper-suspect
        // crypto code is precisely what §9.2.2 forbids.
        // Names MUST match the success-path KAT identifiers byte-for-byte —
        // a downstream report consumer that filters or correlates by the
        // `algorithm` field must see the same identifier whether the test
        // ran or was inhibited. The success branches below populate
        // `algorithm: "<NAME>".to_string()`; this list mirrors them.
        const SKIPPED_TESTS: &[&str] = &[
            "SHA-256",
            "HKDF-SHA256",
            "AES-256-GCM",
            "SHA3-256",
            "HMAC-SHA256",
            "ML-KEM-768",
            "ML-DSA-44",
            "SLH-DSA-SHAKE-192s",
            "FN-DSA-512",
        ];
        for name in SKIPPED_TESTS {
            tests.push(IndividualTestResult {
                algorithm: (*name).to_string(),
                result: SelfTestResult::Fail(
                    "Not run: inhibited by integrity-test failure (FIPS 140-3 §9.2.2)".to_string(),
                ),
                duration_us: None,
            });
        }
        return SelfTestReport {
            overall_result: SelfTestResult::Fail(
                "Module-Integrity Test failed; downstream KATs inhibited per FIPS 140-3 §9.2.2"
                    .to_string(),
            ),
            tests,
            total_duration_us: duration_to_us(start.elapsed()),
        };
    }

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
        // The underlying KAT exercises `fips205::slh_dsa_shake_192s`
        // (ACVP keygen vector + sign/verify roundtrip). The audit-record
        // label must name the parameter set that actually ran, not the
        // smaller `128s` variant — that mislabel previously misrepresented
        // which FIPS 205 parameter set was validated on power-up.
        algorithm: "SLH-DSA-SHAKE-192s".to_string(),
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
        // Mirror `run_power_up_tests`: on Pass, mark the module operational so
        // `is_module_operational()` returns true for callers that routed
        // through `_with_report` instead of `initialize_and_test`. SeqCst
        // pairs with the SeqCst loads on the reader side.
        SELF_TEST_PASSED.store(true, Ordering::SeqCst);
        SelfTestResult::Pass
    } else {
        // Mirror `initialize_and_test`: on Fail, set the FIPS module-error
        // state so subsequent crypto-op gates reject calls. We do NOT
        // `process::abort()` here — the contract of this entry point is to
        // return a diagnostic report. Callers in FIPS deployments who need
        // §9.1's immediate-abort behaviour must inspect the returned report
        // (or call `initialize_and_test`).
        set_module_error(ModuleErrorCode::SelfTestFailure);
        let failed: Vec<_> =
            tests.iter().filter(|t| t.result.is_fail()).map(|t| t.algorithm.clone()).collect();
        SelfTestResult::Fail(format!("Failed tests: {}", failed.join(", ")))
    };

    SelfTestReport { overall_result, tests, total_duration_us: duration_to_us(start.elapsed()) }
}

// =============================================================================
// Module Orchestration (initialize / verify)
// =============================================================================

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
    if !self_tests_passed() {
        return Err(LatticeArcError::ValidationError {
            message: "FIPS module not operational: self-tests have not passed".to_string(),
        });
    }

    // Strict-integrity gate. Under the `fips-strict-integrity` feature the
    // module must not enter operational state when the pre-operational
    // integrity test had no configured HMAC to verify against. This is the
    // right layer for that check — `integrity_test` itself returns a Result
    // so it cannot abort, and `initialize_and_test`'s §9.1 abort is reserved
    // for real tamper or KAT failure. Returning Err here lets the caller
    // handle the deployment-config error without taking the process down.
    //
    // The `not(any(test, feature = "test-utils"))` clause keeps the gate
    // out of unit-test and integration-test builds. Inside this crate's
    // own `cargo test`, `cfg(test)` is true. The integration crate
    // `latticearc-tests` enables the `test-utils` feature on its dep
    // line, so its build of `latticearc` lib is also covered. Downstream
    // consumers (and `latticearc-cli` builds, which deliberately do NOT
    // enable `test-utils`) get the gate intact. Without this scoping, any
    // `--all-features --release` CI test run would enable the gate AND
    // ship no `PRODUCTION_HMAC.txt` — every test that asserts
    // `verify_operational().is_ok()` would then break in lockstep.
    #[cfg(all(feature = "fips-strict-integrity", not(any(test, feature = "test-utils"))))]
    {
        if !INTEGRITY_TEST_CONFIGURED.load(Ordering::SeqCst) {
            return Err(LatticeArcError::ValidationError {
                message: "FIPS module not operational: fips-strict-integrity is enabled but \
                          the pre-operational integrity test (FIPS 140-3 §9.2) could not \
                          establish module authenticity — either no PRODUCTION_HMAC.txt was \
                          provisioned, or current_exe() is not a recognizable LatticeArc \
                          artifact (dynamic-library host or custom-named binary; verify \
                          integrity out-of-band)."
                    .to_string(),
            });
        }
    }

    Ok(())
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
#[expect(
    clippy::indexing_slicing,
    reason = "test assertions index a report vec whose length was just asserted"
)]
mod tests {
    use super::super::FipsStateGuard;
    use super::super::error_state::{clear_error_state, is_module_operational};
    use super::*;

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
        // Module-Integrity (FIPS 140-3 §9.2.2, runs first) + 9 algorithm
        // tests (SHA-256, HKDF, AES-GCM, SHA3-256, HMAC, ML-KEM, ML-DSA,
        // SLH-DSA, FN-DSA).
        assert_eq!(report.tests.len(), 10);
        assert_eq!(report.tests[0].algorithm, "Module-Integrity");
        assert!(report.total_duration_us > 0);

        let cloned = report.clone();
        assert_eq!(cloned.tests.len(), 10);

        let debug = format!("{:?}", report);
        assert!(debug.contains("SelfTestReport"));
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
