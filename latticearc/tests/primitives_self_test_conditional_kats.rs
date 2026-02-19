//! Coverage tests for conditional self-test KAT functions (kat_ml_dsa, kat_slh_dsa, kat_fn_dsa)
//! and run_power_up_tests_with_report error paths.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use latticearc::primitives::self_test::{
    ModuleErrorCode, SelfTestResult, clear_error_state, get_module_error_state,
    initialize_and_test, is_module_operational, kat_aes_256_gcm, kat_fn_dsa, kat_hkdf_sha256,
    kat_ml_dsa, kat_ml_kem_768, kat_sha256, kat_slh_dsa, run_power_up_tests,
    run_power_up_tests_with_report, self_tests_passed, set_module_error, verify_operational,
};

#[test]
fn test_kat_ml_dsa_succeeds() {
    let result = kat_ml_dsa();
    assert!(result.is_ok(), "ML-DSA KAT should succeed: {:?}", result.err());
}

#[test]
fn test_kat_slh_dsa_succeeds() {
    let result = kat_slh_dsa();
    assert!(result.is_ok(), "SLH-DSA KAT should succeed: {:?}", result.err());
}

#[test]
fn test_kat_fn_dsa_succeeds() {
    let result = kat_fn_dsa();
    assert!(result.is_ok(), "FN-DSA KAT should succeed: {:?}", result.err());
}

#[test]
fn test_kat_sha256_succeeds() {
    let result = kat_sha256();
    assert!(result.is_ok());
}

#[test]
fn test_kat_hkdf_sha256_succeeds() {
    let result = kat_hkdf_sha256();
    assert!(result.is_ok());
}

#[test]
fn test_kat_aes_256_gcm_succeeds() {
    let result = kat_aes_256_gcm();
    assert!(result.is_ok());
}

#[test]
fn test_kat_ml_kem_768_succeeds() {
    let result = kat_ml_kem_768();
    assert!(result.is_ok());
}

#[test]
fn test_run_power_up_tests_pass() {
    let result = run_power_up_tests();
    assert!(result.is_pass(), "Power-up tests should pass");
}

#[test]
fn test_run_power_up_tests_with_report_all_pass() {
    let report = run_power_up_tests_with_report();
    assert!(report.overall_result.is_pass());
    assert!(!report.tests.is_empty());
    for test in &report.tests {
        assert!(test.result.is_pass(), "Test {} should pass", test.algorithm);
        assert!(test.duration_us.is_some());
    }
    assert!(report.total_duration_us > 0);
}

#[test]
fn test_module_operational_after_init() {
    clear_error_state();
    let result = initialize_and_test();
    assert!(result.is_pass());
    assert!(is_module_operational());
    assert!(self_tests_passed());
    assert!(verify_operational().is_ok());
}

#[test]
fn test_module_error_codes_exhaustive() {
    // Test all error codes from_u32 and description
    let codes = [
        (0, ModuleErrorCode::NoError, false),
        (1, ModuleErrorCode::SelfTestFailure, true),
        (2, ModuleErrorCode::EntropyFailure, true),
        (3, ModuleErrorCode::IntegrityFailure, true),
        (4, ModuleErrorCode::CriticalCryptoError, true),
        (5, ModuleErrorCode::KeyZeroizationFailure, true),
        (6, ModuleErrorCode::AuthenticationFailure, true),
        (7, ModuleErrorCode::HsmError, true),
        (255, ModuleErrorCode::UnknownCriticalError, true),
        (100, ModuleErrorCode::UnknownCriticalError, true),
        (999, ModuleErrorCode::UnknownCriticalError, true),
    ];

    for (val, expected, is_err) in codes {
        let code = ModuleErrorCode::from_u32(val);
        assert_eq!(code, expected, "from_u32({}) should be {:?}", val, expected);
        assert_eq!(code.is_error(), is_err, "is_error for {:?}", code);
        // Exercise description
        let desc = code.description();
        assert!(!desc.is_empty());
    }
}

#[test]
fn test_module_error_state_lifecycle() {
    clear_error_state();
    let _ = initialize_and_test();

    // Module should be operational
    assert!(is_module_operational());

    // Set error
    set_module_error(ModuleErrorCode::SelfTestFailure);
    assert!(!is_module_operational());
    let state = get_module_error_state();
    assert_eq!(state.error_code, ModuleErrorCode::SelfTestFailure);
    assert!(state.is_error());
    assert!(state.timestamp > 0);

    // Verify operational fails with proper error
    let result = verify_operational();
    assert!(result.is_err());

    // Clear and re-initialize
    clear_error_state();
    let result = initialize_and_test();
    assert!(result.is_pass());
    assert!(is_module_operational());
}

#[test]
fn test_self_test_result_variants() {
    let pass = SelfTestResult::Pass;
    assert!(pass.is_pass());
    assert!(!pass.is_fail());

    let fail = SelfTestResult::Fail("test error".to_string());
    assert!(!fail.is_pass());
    assert!(fail.is_fail());

    // Clone and eq
    let pass2 = pass.clone();
    assert_eq!(pass, pass2);
    let fail2 = fail.clone();
    assert_eq!(fail, fail2);
    assert_ne!(pass, fail);
}
