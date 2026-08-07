#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use super::SELF_TEST_PASSED;

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
    // use SeqCst loads to match the SeqCst stores in
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

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::super::FipsStateGuard;
    use super::super::post::{initialize_and_test, verify_operational};
    use super::*;

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
    fn test_current_timestamp_reasonable_succeeds() {
        let ts = current_timestamp();
        // Should be after 2020-01-01 (1577836800)
        assert!(ts > 1_577_836_800, "Timestamp should be after 2020");
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
}
