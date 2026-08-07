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

use std::sync::atomic::AtomicBool;

// Split from a single ~3.3 KLoC file into per-concern submodules:
//   - `kat`: per-algorithm Known Answer Tests
//   - `integrity`: FIPS 140-3 §9.2.2 software/firmware integrity test
//   - `error_state`: module error-state machine (FIPS 140-3 §9.6)
//   - `post`: power-up orchestration (runs the above, exposes the
//     public entry points)
// Submodules are private; every previously-public
// `primitives::self_test::X` path is preserved below via `pub use`.
mod error_state;
mod integrity;
mod kat;
mod post;

pub use error_state::{
    ModuleErrorCode, ModuleErrorState, get_module_error_state, is_module_operational,
    self_tests_passed, set_module_error,
};
#[cfg(any(test, feature = "test-utils"))]
pub use error_state::{clear_error_state, restore_operational_state};
pub use integrity::integrity_test;
pub use kat::{
    kat_aes_256_gcm, kat_fn_dsa, kat_hkdf_sha256, kat_hmac_sha256, kat_ml_dsa, kat_sha3_256,
    kat_sha256, kat_slh_dsa, roundtrip_ml_kem_768,
};
pub use post::{
    IndividualTestResult, SelfTestReport, SelfTestResult, initialize_and_test, run_power_up_tests,
    run_power_up_tests_with_report, verify_operational,
};

// =============================================================================
// Module State Management
// =============================================================================
//
// These two flags are genuinely shared across the split: `kat` and
// `integrity` don't touch them, but `post` (power-up orchestration) and
// `error_state` (the FIPS §9.6 error-state machine) both read and write
// `SELF_TEST_PASSED`, and both `integrity` (sets it) and `post` (reads it
// in the strict-integrity gate) touch `INTEGRITY_TEST_CONFIGURED`.
// Declared here, at the shared parent, rather than arbitrarily homed in
// one submodule: a plain private item declared in this file is visible to
// `self_test` and all of its descendant modules (including each
// submodule's own `tests`), which is exactly the access shape needed
// without exceeding the `pub(super)` promotion ceiling used elsewhere in
// this split.

static SELF_TEST_PASSED: AtomicBool = AtomicBool::new(false);

/// Records whether the pre-operational integrity test had a real expected
/// HMAC to compare against. Set to `true` by `integrity_test` only after a
/// configured `EXPECTED_HMAC` was consumed; stays `false` if the test
/// short-circuited because no `PRODUCTION_HMAC.txt` was provisioned. The
/// `fips-strict-integrity` branch in `verify_operational` reads this flag
/// to refuse operational entry on a deployment-misconfiguration that
/// previously would have silently passed.
static INTEGRITY_TEST_CONFIGURED: AtomicBool = AtomicBool::new(false);

// =============================================================================
// Shared test support
// =============================================================================
//
// `FipsStateGuard` is used by tests in both `error_state` (which owns
// `restore_operational_state`) and `post` (which owns
// `verify_operational`/`initialize_and_test`). Declared here for the same
// reason as the statics above: a private item here is visible to every
// submodule's `tests` without needing anything above `pub(super)`.

#[cfg(test)]
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
#[cfg(test)]
impl FipsStateGuard {
    const fn new() -> Self {
        Self { _not_send_or_sync: core::marker::PhantomData }
    }
}
#[cfg(test)]
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
