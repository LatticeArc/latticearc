//! Comprehensive tests for arc-validation/src/nist_kat/mod.rs
//!
//! This test module covers:
//! - Module-level exports and re-exports
//! - All public functions (decode_hex, KatTestResult, NistKatError)
//! - KatRunner and KatSummary functionality
//! - Integration between submodules
//! - Error handling
//! - Edge cases

#![allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::float_cmp,
    clippy::redundant_closure,
    clippy::redundant_clone,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_lossless,
    clippy::single_match_else,
    clippy::default_constructed_unit_structs,
    clippy::manual_is_multiple_of,
    clippy::needless_borrows_for_generic_args,
    clippy::print_stdout,
    clippy::unnecessary_unwrap,
    clippy::unnecessary_literal_unwrap,
    clippy::to_string_in_format_args,
    clippy::expect_fun_call,
    clippy::clone_on_copy,
    clippy::cast_precision_loss,
    clippy::useless_format,
    clippy::assertions_on_constants,
    clippy::drop_non_drop,
    clippy::redundant_closure_for_method_calls,
    clippy::unnecessary_map_or,
    clippy::print_stderr,
    clippy::inconsistent_digit_grouping,
    clippy::useless_vec
)]

use arc_validation::nist_kat::{
    KatRunner, KatSummary, KatTestResult, NistKatError, aes_gcm_kat, chacha20_poly1305_kat,
    decode_hex, hkdf_kat, hmac_kat, ml_dsa_kat, ml_kem_kat, sha2_kat,
};

// ============================================================================
// Module Re-export Tests
// ============================================================================

mod re_export_tests {
    use super::*;

    #[test]
    fn test_kat_runner_exported() {
        // Verify KatRunner is properly exported
        let runner = KatRunner::new();
        assert!(runner.summary().total == 0);
    }

    #[test]
    fn test_kat_summary_exported() {
        // Verify KatSummary is properly exported
        let summary = KatSummary::new();
        assert_eq!(summary.total, 0);
        assert_eq!(summary.passed, 0);
        assert_eq!(summary.failed, 0);
    }

    #[test]
    fn test_aes_gcm_kat_module_exported() {
        // Verify AES-GCM KAT module is accessible
        assert!(!aes_gcm_kat::AES_128_GCM_VECTORS.is_empty());
        assert!(!aes_gcm_kat::AES_256_GCM_VECTORS.is_empty());
    }

    #[test]
    fn test_sha2_kat_module_exported() {
        // Verify SHA2 KAT module is accessible
        assert!(!sha2_kat::SHA256_VECTORS.is_empty());
        assert!(!sha2_kat::SHA224_VECTORS.is_empty());
        assert!(!sha2_kat::SHA384_VECTORS.is_empty());
        assert!(!sha2_kat::SHA512_VECTORS.is_empty());
    }

    #[test]
    fn test_hkdf_kat_module_exported() {
        // Verify HKDF KAT module is accessible
        assert!(!hkdf_kat::HKDF_SHA256_VECTORS.is_empty());
    }

    #[test]
    fn test_hmac_kat_module_exported() {
        // Verify HMAC KAT module is accessible
        assert!(!hmac_kat::HMAC_VECTORS.is_empty());
    }

    #[test]
    fn test_chacha20_poly1305_kat_module_exported() {
        // Verify ChaCha20-Poly1305 KAT module is accessible
        assert!(!chacha20_poly1305_kat::CHACHA20_POLY1305_VECTORS.is_empty());
    }

    #[test]
    fn test_ml_kem_kat_module_exported() {
        // Verify ML-KEM KAT module is accessible
        assert!(!ml_kem_kat::ML_KEM_512_VECTORS.is_empty());
        assert!(!ml_kem_kat::ML_KEM_768_VECTORS.is_empty());
        assert!(!ml_kem_kat::ML_KEM_1024_VECTORS.is_empty());
    }

    #[test]
    fn test_ml_dsa_kat_module_exported() {
        // Verify ML-DSA KAT module is accessible
        assert!(!ml_dsa_kat::ML_DSA_44_VECTORS.is_empty());
        assert!(!ml_dsa_kat::ML_DSA_65_VECTORS.is_empty());
        assert!(!ml_dsa_kat::ML_DSA_87_VECTORS.is_empty());
    }
}

// ============================================================================
// decode_hex Function Tests
// ============================================================================

mod decode_hex_tests {
    use super::*;

    #[test]
    fn test_decode_hex_empty_string() {
        let result = decode_hex("");
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn test_decode_hex_valid_lowercase() {
        let result = decode_hex("0123456789abcdef");
        assert!(result.is_ok());
        let bytes = result.unwrap();
        assert_eq!(bytes, vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]);
    }

    #[test]
    fn test_decode_hex_valid_uppercase() {
        let result = decode_hex("0123456789ABCDEF");
        assert!(result.is_ok());
        let bytes = result.unwrap();
        assert_eq!(bytes, vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]);
    }

    #[test]
    fn test_decode_hex_mixed_case() {
        let result = decode_hex("0123456789AbCdEf");
        assert!(result.is_ok());
        let bytes = result.unwrap();
        assert_eq!(bytes, vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]);
    }

    #[test]
    fn test_decode_hex_single_byte() {
        let result = decode_hex("ff");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), vec![0xff]);
    }

    #[test]
    fn test_decode_hex_all_zeros() {
        let result = decode_hex("0000000000000000");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), vec![0, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn test_decode_hex_all_ones() {
        let result = decode_hex("ffffffff");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), vec![0xff, 0xff, 0xff, 0xff]);
    }

    #[test]
    fn test_decode_hex_invalid_char() {
        let result = decode_hex("0g");
        assert!(result.is_err());
        match result {
            Err(NistKatError::HexError(_)) => {}
            _ => panic!("Expected HexError"),
        }
    }

    #[test]
    fn test_decode_hex_odd_length() {
        let result = decode_hex("123");
        assert!(result.is_err());
        match result {
            Err(NistKatError::HexError(_)) => {}
            _ => panic!("Expected HexError"),
        }
    }

    #[test]
    fn test_decode_hex_with_spaces() {
        let result = decode_hex("01 23");
        assert!(result.is_err());
        match result {
            Err(NistKatError::HexError(_)) => {}
            _ => panic!("Expected HexError"),
        }
    }

    #[test]
    fn test_decode_hex_with_prefix() {
        let result = decode_hex("0x0123");
        assert!(result.is_err());
        match result {
            Err(NistKatError::HexError(_)) => {}
            _ => panic!("Expected HexError"),
        }
    }

    #[test]
    fn test_decode_hex_unicode() {
        let result = decode_hex("\u{00e9}");
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_hex_long_string() {
        // Test with a 128-byte (256 hex chars) string
        let hex_str = "00".repeat(128);
        let result = decode_hex(&hex_str);
        assert!(result.is_ok());
        let bytes = result.unwrap();
        assert_eq!(bytes.len(), 128);
        assert!(bytes.iter().all(|&b| b == 0));
    }
}

// ============================================================================
// NistKatError Tests
// ============================================================================

mod nist_kat_error_tests {
    use super::*;

    #[test]
    fn test_error_test_failed() {
        let error = NistKatError::TestFailed {
            algorithm: "AES-256-GCM".to_string(),
            test_name: "Test-1".to_string(),
            message: "Output mismatch".to_string(),
        };
        let error_string = error.to_string();
        assert!(error_string.contains("AES-256-GCM"));
        assert!(error_string.contains("Test-1"));
        assert!(error_string.contains("Output mismatch"));
    }

    #[test]
    fn test_error_hex_error() {
        let error = NistKatError::HexError("Invalid hex character".to_string());
        let error_string = error.to_string();
        assert!(error_string.contains("Invalid hex character"));
    }

    #[test]
    fn test_error_implementation_error() {
        let error = NistKatError::ImplementationError("Key creation failed".to_string());
        let error_string = error.to_string();
        assert!(error_string.contains("Key creation failed"));
    }

    #[test]
    fn test_error_unsupported_algorithm() {
        let error = NistKatError::UnsupportedAlgorithm("UNKNOWN-ALG".to_string());
        let error_string = error.to_string();
        assert!(error_string.contains("UNKNOWN-ALG"));
    }

    #[test]
    fn test_error_debug_format() {
        let error = NistKatError::TestFailed {
            algorithm: "SHA-256".to_string(),
            test_name: "Test-2".to_string(),
            message: "Hash mismatch".to_string(),
        };
        let debug_str = format!("{:?}", error);
        assert!(debug_str.contains("TestFailed"));
    }
}

// ============================================================================
// KatTestResult Tests
// ============================================================================

mod kat_test_result_tests {
    use super::*;

    #[test]
    fn test_passed_result() {
        let result =
            KatTestResult::passed("Test-Case-1".to_string(), "AES-128-GCM".to_string(), 1000);
        assert!(result.passed);
        assert_eq!(result.test_case, "Test-Case-1");
        assert_eq!(result.algorithm, "AES-128-GCM");
        assert!(result.error_message.is_none());
        assert_eq!(result.execution_time_us, 1000);
    }

    #[test]
    fn test_failed_result() {
        let result = KatTestResult::failed(
            "Test-Case-2".to_string(),
            "SHA-256".to_string(),
            "Hash mismatch".to_string(),
            500,
        );
        assert!(!result.passed);
        assert_eq!(result.test_case, "Test-Case-2");
        assert_eq!(result.algorithm, "SHA-256");
        assert_eq!(result.error_message, Some("Hash mismatch".to_string()));
        assert_eq!(result.execution_time_us, 500);
    }

    #[test]
    fn test_result_clone() {
        let result =
            KatTestResult::passed("Test-Clone".to_string(), "HMAC-SHA512".to_string(), 200);
        let cloned = result.clone();
        assert_eq!(result.test_case, cloned.test_case);
        assert_eq!(result.algorithm, cloned.algorithm);
        assert_eq!(result.passed, cloned.passed);
        assert_eq!(result.execution_time_us, cloned.execution_time_us);
    }

    #[test]
    fn test_result_debug() {
        let result = KatTestResult::passed("Test-Debug".to_string(), "HKDF".to_string(), 100);
        let debug_str = format!("{:?}", result);
        assert!(debug_str.contains("Test-Debug"));
        assert!(debug_str.contains("HKDF"));
    }

    #[test]
    fn test_passed_with_zero_time() {
        let result = KatTestResult::passed("Zero-Time".to_string(), "Fast-Test".to_string(), 0);
        assert!(result.passed);
        assert_eq!(result.execution_time_us, 0);
    }

    #[test]
    fn test_failed_with_empty_error_message() {
        let result =
            KatTestResult::failed("Empty-Error".to_string(), "Test".to_string(), "".to_string(), 1);
        assert!(!result.passed);
        assert_eq!(result.error_message, Some("".to_string()));
    }
}

// ============================================================================
// KatSummary Tests
// ============================================================================

mod kat_summary_tests {
    use super::*;

    #[test]
    fn test_new_summary() {
        let summary = KatSummary::new();
        assert_eq!(summary.total, 0);
        assert_eq!(summary.passed, 0);
        assert_eq!(summary.failed, 0);
        assert!(summary.results.is_empty());
        assert_eq!(summary.total_time_ms, 0);
    }

    #[test]
    fn test_default_summary() {
        let summary = KatSummary::default();
        assert_eq!(summary.total, 0);
        assert_eq!(summary.passed, 0);
        assert_eq!(summary.failed, 0);
    }

    #[test]
    fn test_add_passed_result() {
        let mut summary = KatSummary::new();
        let result = KatTestResult::passed("Test-1".to_string(), "Algo-1".to_string(), 1000);
        summary.add_result(result);

        assert_eq!(summary.total, 1);
        assert_eq!(summary.passed, 1);
        assert_eq!(summary.failed, 0);
        assert_eq!(summary.results.len(), 1);
        assert_eq!(summary.total_time_ms, 1); // 1000us / 1000 = 1ms
    }

    #[test]
    fn test_add_failed_result() {
        let mut summary = KatSummary::new();
        let result = KatTestResult::failed(
            "Test-2".to_string(),
            "Algo-2".to_string(),
            "Error".to_string(),
            2000,
        );
        summary.add_result(result);

        assert_eq!(summary.total, 1);
        assert_eq!(summary.passed, 0);
        assert_eq!(summary.failed, 1);
    }

    #[test]
    fn test_add_multiple_results() {
        let mut summary = KatSummary::new();

        // Add 3 passed, 2 failed
        summary.add_result(KatTestResult::passed("P1".to_string(), "A1".to_string(), 1000));
        summary.add_result(KatTestResult::passed("P2".to_string(), "A1".to_string(), 1000));
        summary.add_result(KatTestResult::passed("P3".to_string(), "A2".to_string(), 1000));
        summary.add_result(KatTestResult::failed(
            "F1".to_string(),
            "A2".to_string(),
            "E1".to_string(),
            1000,
        ));
        summary.add_result(KatTestResult::failed(
            "F2".to_string(),
            "A3".to_string(),
            "E2".to_string(),
            1000,
        ));

        assert_eq!(summary.total, 5);
        assert_eq!(summary.passed, 3);
        assert_eq!(summary.failed, 2);
        assert_eq!(summary.results.len(), 5);
    }

    #[test]
    fn test_all_passed_true() {
        let mut summary = KatSummary::new();
        summary.add_result(KatTestResult::passed("T1".to_string(), "A".to_string(), 0));
        summary.add_result(KatTestResult::passed("T2".to_string(), "A".to_string(), 0));

        assert!(summary.all_passed());
    }

    #[test]
    fn test_all_passed_false() {
        let mut summary = KatSummary::new();
        summary.add_result(KatTestResult::passed("T1".to_string(), "A".to_string(), 0));
        summary.add_result(KatTestResult::failed(
            "T2".to_string(),
            "A".to_string(),
            "E".to_string(),
            0,
        ));

        assert!(!summary.all_passed());
    }

    #[test]
    fn test_all_passed_empty() {
        let summary = KatSummary::new();
        assert!(summary.all_passed()); // No failures means all passed
    }

    #[test]
    fn test_pass_rate_all_passed() {
        let mut summary = KatSummary::new();
        summary.add_result(KatTestResult::passed("T1".to_string(), "A".to_string(), 0));
        summary.add_result(KatTestResult::passed("T2".to_string(), "A".to_string(), 0));

        assert!((summary.pass_rate() - 100.0).abs() < 0.001);
    }

    #[test]
    fn test_pass_rate_all_failed() {
        let mut summary = KatSummary::new();
        summary.add_result(KatTestResult::failed(
            "T1".to_string(),
            "A".to_string(),
            "E".to_string(),
            0,
        ));
        summary.add_result(KatTestResult::failed(
            "T2".to_string(),
            "A".to_string(),
            "E".to_string(),
            0,
        ));

        assert!((summary.pass_rate() - 0.0).abs() < 0.001);
    }

    #[test]
    fn test_pass_rate_fifty_percent() {
        let mut summary = KatSummary::new();
        summary.add_result(KatTestResult::passed("T1".to_string(), "A".to_string(), 0));
        summary.add_result(KatTestResult::failed(
            "T2".to_string(),
            "A".to_string(),
            "E".to_string(),
            0,
        ));

        assert!((summary.pass_rate() - 50.0).abs() < 0.001);
    }

    #[test]
    fn test_pass_rate_empty() {
        let summary = KatSummary::new();
        assert!((summary.pass_rate() - 0.0).abs() < 0.001);
    }

    #[test]
    fn test_summary_clone() {
        let mut summary = KatSummary::new();
        summary.add_result(KatTestResult::passed("T1".to_string(), "A".to_string(), 1000));
        let cloned = summary.clone();

        assert_eq!(summary.total, cloned.total);
        assert_eq!(summary.passed, cloned.passed);
        assert_eq!(summary.results.len(), cloned.results.len());
    }

    #[test]
    fn test_summary_print_does_not_panic() {
        // Just verify print doesn't panic with various states
        let mut summary = KatSummary::new();
        summary.print(); // Empty

        summary.add_result(KatTestResult::passed("T".to_string(), "A".to_string(), 0));
        summary.print(); // With passed

        summary.add_result(KatTestResult::failed(
            "T2".to_string(),
            "A".to_string(),
            "Error".to_string(),
            0,
        ));
        summary.print(); // With failed
    }
}

// ============================================================================
// KatRunner Tests
// ============================================================================

mod kat_runner_tests {
    use super::*;

    #[test]
    fn test_new_runner() {
        let runner = KatRunner::new();
        let summary = runner.summary();
        assert_eq!(summary.total, 0);
    }

    #[test]
    fn test_default_runner() {
        let runner = KatRunner::default();
        assert_eq!(runner.summary().total, 0);
    }

    #[test]
    fn test_run_passing_test() {
        let mut runner = KatRunner::new();
        runner.run_test("Test-1", "Algo", || Ok(()));

        let summary = runner.summary();
        assert_eq!(summary.total, 1);
        assert_eq!(summary.passed, 1);
        assert_eq!(summary.failed, 0);
    }

    #[test]
    fn test_run_failing_test() {
        let mut runner = KatRunner::new();
        runner.run_test("Test-2", "Algo", || {
            Err(NistKatError::TestFailed {
                algorithm: "Algo".to_string(),
                test_name: "Test-2".to_string(),
                message: "Failure".to_string(),
            })
        });

        let summary = runner.summary();
        assert_eq!(summary.total, 1);
        assert_eq!(summary.passed, 0);
        assert_eq!(summary.failed, 1);
    }

    #[test]
    fn test_run_multiple_tests() {
        let mut runner = KatRunner::new();

        // Two passing tests
        runner.run_test("Pass-1", "A1", || Ok(()));
        runner.run_test("Pass-2", "A1", || Ok(()));

        // One failing test
        runner.run_test("Fail-1", "A2", || {
            Err(NistKatError::ImplementationError("Error".to_string()))
        });

        let summary = runner.summary();
        assert_eq!(summary.total, 3);
        assert_eq!(summary.passed, 2);
        assert_eq!(summary.failed, 1);
    }

    #[test]
    fn test_finish_returns_summary() {
        let mut runner = KatRunner::new();
        runner.run_test("Test", "Algo", || Ok(()));

        let summary = runner.finish();
        assert_eq!(summary.total, 1);
        assert!(summary.all_passed());
    }

    #[test]
    fn test_runner_records_execution_time() {
        let mut runner = KatRunner::new();
        runner.run_test("Slow-Test", "Algo", || {
            std::thread::sleep(std::time::Duration::from_millis(10));
            Ok(())
        });

        let summary = runner.summary();
        assert!(summary.results[0].execution_time_us > 0);
    }

    #[test]
    fn test_runner_hex_error() {
        let mut runner = KatRunner::new();
        runner.run_test("Hex-Test", "Algo", || Err(NistKatError::HexError("bad".to_string())));

        assert!(!runner.summary().all_passed());
        assert!(runner.summary().results[0].error_message.as_ref().unwrap().contains("Hex"));
    }

    #[test]
    fn test_runner_unsupported_algorithm() {
        let mut runner = KatRunner::new();
        runner.run_test("Unsupported", "Unknown", || {
            Err(NistKatError::UnsupportedAlgorithm("Unknown".to_string()))
        });

        assert_eq!(runner.summary().failed, 1);
    }
}

// ============================================================================
// Integration Tests - Submodule Functions
// ============================================================================

mod submodule_function_tests {
    use super::*;

    #[test]
    fn test_run_aes_128_gcm_kat() {
        let result = aes_gcm_kat::run_aes_128_gcm_kat();
        assert!(result.is_ok(), "AES-128-GCM KAT failed: {:?}", result);
    }

    #[test]
    fn test_run_aes_256_gcm_kat() {
        let result = aes_gcm_kat::run_aes_256_gcm_kat();
        assert!(result.is_ok(), "AES-256-GCM KAT failed: {:?}", result);
    }

    #[test]
    fn test_run_sha256_kat() {
        let result = sha2_kat::run_sha256_kat();
        assert!(result.is_ok(), "SHA-256 KAT failed: {:?}", result);
    }

    #[test]
    fn test_run_sha224_kat() {
        let result = sha2_kat::run_sha224_kat();
        assert!(result.is_ok(), "SHA-224 KAT failed: {:?}", result);
    }

    #[test]
    fn test_run_sha384_kat() {
        let result = sha2_kat::run_sha384_kat();
        assert!(result.is_ok(), "SHA-384 KAT failed: {:?}", result);
    }

    #[test]
    fn test_run_sha512_kat() {
        let result = sha2_kat::run_sha512_kat();
        assert!(result.is_ok(), "SHA-512 KAT failed: {:?}", result);
    }

    #[test]
    fn test_run_sha512_224_kat() {
        let result = sha2_kat::run_sha512_224_kat();
        assert!(result.is_ok(), "SHA-512/224 KAT failed: {:?}", result);
    }

    #[test]
    fn test_run_sha512_256_kat() {
        let result = sha2_kat::run_sha512_256_kat();
        assert!(result.is_ok(), "SHA-512/256 KAT failed: {:?}", result);
    }

    #[test]
    fn test_run_hkdf_sha256_kat() {
        let result = hkdf_kat::run_hkdf_sha256_kat();
        assert!(result.is_ok(), "HKDF-SHA256 KAT failed: {:?}", result);
    }

    #[test]
    fn test_run_hmac_sha224_kat() {
        let result = hmac_kat::run_hmac_sha224_kat();
        assert!(result.is_ok(), "HMAC-SHA224 KAT failed: {:?}", result);
    }

    #[test]
    fn test_run_hmac_sha256_kat() {
        let result = hmac_kat::run_hmac_sha256_kat();
        assert!(result.is_ok(), "HMAC-SHA256 KAT failed: {:?}", result);
    }

    #[test]
    fn test_run_hmac_sha384_kat() {
        let result = hmac_kat::run_hmac_sha384_kat();
        assert!(result.is_ok(), "HMAC-SHA384 KAT failed: {:?}", result);
    }

    #[test]
    fn test_run_hmac_sha512_kat() {
        let result = hmac_kat::run_hmac_sha512_kat();
        assert!(result.is_ok(), "HMAC-SHA512 KAT failed: {:?}", result);
    }

    #[test]
    fn test_run_chacha20_poly1305_kat() {
        let result = chacha20_poly1305_kat::run_chacha20_poly1305_kat();
        assert!(result.is_ok(), "ChaCha20-Poly1305 KAT failed: {:?}", result);
    }

    #[test]
    fn test_run_ml_kem_512_kat() {
        let result = ml_kem_kat::run_ml_kem_512_kat();
        assert!(result.is_ok(), "ML-KEM-512 KAT failed: {:?}", result);
    }

    #[test]
    fn test_run_ml_kem_768_kat() {
        let result = ml_kem_kat::run_ml_kem_768_kat();
        assert!(result.is_ok(), "ML-KEM-768 KAT failed: {:?}", result);
    }

    #[test]
    fn test_run_ml_kem_1024_kat() {
        let result = ml_kem_kat::run_ml_kem_1024_kat();
        assert!(result.is_ok(), "ML-KEM-1024 KAT failed: {:?}", result);
    }

    #[test]
    fn test_run_ml_dsa_44_kat() {
        let result = ml_dsa_kat::run_ml_dsa_44_kat();
        assert!(result.is_ok(), "ML-DSA-44 KAT failed: {:?}", result);
    }

    #[test]
    fn test_run_ml_dsa_65_kat() {
        let result = ml_dsa_kat::run_ml_dsa_65_kat();
        assert!(result.is_ok(), "ML-DSA-65 KAT failed: {:?}", result);
    }

    #[test]
    fn test_run_ml_dsa_87_kat() {
        let result = ml_dsa_kat::run_ml_dsa_87_kat();
        assert!(result.is_ok(), "ML-DSA-87 KAT failed: {:?}", result);
    }
}

// ============================================================================
// Integration Tests - KatRunner with Real Tests
// ============================================================================

mod kat_runner_integration_tests {
    use super::*;

    #[test]
    fn test_runner_with_aes_gcm_kats() {
        let mut runner = KatRunner::new();

        runner.run_test("AES-128-GCM-All", "AES-128-GCM", || aes_gcm_kat::run_aes_128_gcm_kat());
        runner.run_test("AES-256-GCM-All", "AES-256-GCM", || aes_gcm_kat::run_aes_256_gcm_kat());

        let summary = runner.finish();
        assert!(summary.all_passed());
        assert_eq!(summary.total, 2);
    }

    #[test]
    fn test_runner_with_sha2_kats() {
        let mut runner = KatRunner::new();

        runner.run_test("SHA-224", "SHA-224", || sha2_kat::run_sha224_kat());
        runner.run_test("SHA-256", "SHA-256", || sha2_kat::run_sha256_kat());
        runner.run_test("SHA-384", "SHA-384", || sha2_kat::run_sha384_kat());
        runner.run_test("SHA-512", "SHA-512", || sha2_kat::run_sha512_kat());
        runner.run_test("SHA-512/224", "SHA-512/224", || sha2_kat::run_sha512_224_kat());
        runner.run_test("SHA-512/256", "SHA-512/256", || sha2_kat::run_sha512_256_kat());

        let summary = runner.finish();
        assert!(summary.all_passed());
        assert_eq!(summary.total, 6);
    }

    #[test]
    fn test_runner_with_hmac_kats() {
        let mut runner = KatRunner::new();

        runner.run_test("HMAC-SHA224", "HMAC-SHA224", || hmac_kat::run_hmac_sha224_kat());
        runner.run_test("HMAC-SHA256", "HMAC-SHA256", || hmac_kat::run_hmac_sha256_kat());
        runner.run_test("HMAC-SHA384", "HMAC-SHA384", || hmac_kat::run_hmac_sha384_kat());
        runner.run_test("HMAC-SHA512", "HMAC-SHA512", || hmac_kat::run_hmac_sha512_kat());

        let summary = runner.finish();
        assert!(summary.all_passed());
        assert_eq!(summary.total, 4);
    }

    #[test]
    fn test_runner_with_pqc_kats() {
        let mut runner = KatRunner::new();

        runner.run_test("ML-KEM-512", "ML-KEM-512", || ml_kem_kat::run_ml_kem_512_kat());
        runner.run_test("ML-KEM-768", "ML-KEM-768", || ml_kem_kat::run_ml_kem_768_kat());
        runner.run_test("ML-KEM-1024", "ML-KEM-1024", || ml_kem_kat::run_ml_kem_1024_kat());

        let summary = runner.finish();
        assert!(summary.all_passed());
        assert_eq!(summary.total, 3);
    }

    #[test]
    fn test_runner_comprehensive_kat_suite() {
        let mut runner = KatRunner::new();

        // Symmetric crypto
        runner.run_test("AES-128-GCM", "AEAD", || aes_gcm_kat::run_aes_128_gcm_kat());
        runner.run_test("AES-256-GCM", "AEAD", || aes_gcm_kat::run_aes_256_gcm_kat());
        runner.run_test("ChaCha20-Poly1305", "AEAD", || {
            chacha20_poly1305_kat::run_chacha20_poly1305_kat()
        });

        // Hashing
        runner.run_test("SHA-256", "Hash", || sha2_kat::run_sha256_kat());

        // Key derivation
        runner.run_test("HKDF-SHA256", "KDF", || hkdf_kat::run_hkdf_sha256_kat());

        // MACs
        runner.run_test("HMAC-SHA256", "MAC", || hmac_kat::run_hmac_sha256_kat());

        // Post-quantum
        runner.run_test("ML-KEM-768", "PQC-KEM", || ml_kem_kat::run_ml_kem_768_kat());
        runner.run_test("ML-DSA-65", "PQC-DSA", || ml_dsa_kat::run_ml_dsa_65_kat());

        let summary = runner.finish();
        summary.print();
        assert!(
            summary.all_passed(),
            "Comprehensive KAT suite failed with {} failures",
            summary.failed
        );
        assert_eq!(summary.total, 8);
    }
}

// ============================================================================
// Edge Cases and Error Condition Tests
// ============================================================================

mod edge_case_tests {
    use super::*;

    #[test]
    fn test_vector_struct_field_access() {
        // Test that we can access test vector struct fields
        let aes_vector = &aes_gcm_kat::AES_128_GCM_VECTORS[0];
        assert!(!aes_vector.test_name.is_empty());
        assert!(!aes_vector.key.is_empty());
        assert!(!aes_vector.nonce.is_empty());
        // AAD can be empty
        // Plaintext can be empty (Test Case 1)
        assert!(!aes_vector.expected_tag.is_empty());
    }

    #[test]
    fn test_sha2_vector_struct_field_access() {
        let sha_vector = &sha2_kat::SHA256_VECTORS[0];
        assert!(!sha_vector.test_name.is_empty());
        // Message can be empty
        assert!(!sha_vector.expected_hash.is_empty());
    }

    #[test]
    fn test_hkdf_vector_struct_field_access() {
        let hkdf_vector = &hkdf_kat::HKDF_SHA256_VECTORS[0];
        assert!(!hkdf_vector.test_name.is_empty());
        assert!(!hkdf_vector.ikm.is_empty());
        // Salt can be empty
        // Info can be empty
        assert!(hkdf_vector.length > 0);
        assert!(!hkdf_vector.expected_prk.is_empty());
        assert!(!hkdf_vector.expected_okm.is_empty());
    }

    #[test]
    fn test_hmac_vector_struct_field_access() {
        let hmac_vector = &hmac_kat::HMAC_VECTORS[0];
        assert!(!hmac_vector.test_name.is_empty());
        assert!(!hmac_vector.key.is_empty());
        assert!(!hmac_vector.message.is_empty());
        assert!(!hmac_vector.expected_mac_sha224.is_empty());
        assert!(!hmac_vector.expected_mac_sha256.is_empty());
        assert!(!hmac_vector.expected_mac_sha384.is_empty());
        assert!(!hmac_vector.expected_mac_sha512.is_empty());
    }

    #[test]
    fn test_ml_kem_vector_struct_field_access() {
        let kem_vector = &ml_kem_kat::ML_KEM_512_VECTORS[0];
        assert!(!kem_vector.test_name.is_empty());
        assert!(!kem_vector.seed.is_empty());
    }

    #[test]
    fn test_ml_dsa_vector_struct_field_access() {
        let dsa_vector = &ml_dsa_kat::ML_DSA_44_VECTORS[0];
        assert!(!dsa_vector.test_name.is_empty());
        assert!(!dsa_vector.seed.is_empty());
        // Message can be empty
    }

    #[test]
    fn test_chacha20_poly1305_vector_struct_field_access() {
        let cc_vector = &chacha20_poly1305_kat::CHACHA20_POLY1305_VECTORS[0];
        assert!(!cc_vector.test_name.is_empty());
        assert!(!cc_vector.key.is_empty());
        assert!(!cc_vector.nonce.is_empty());
        // AAD can be empty
        assert!(!cc_vector.plaintext.is_empty());
        assert!(!cc_vector.expected_ciphertext.is_empty());
        assert!(!cc_vector.expected_tag.is_empty());
    }

    #[test]
    fn test_runner_handles_mixed_results() {
        let mut runner = KatRunner::new();

        runner.run_test("Pass", "Algo", || Ok(()));
        runner.run_test("Fail", "Algo", || {
            Err(NistKatError::TestFailed {
                algorithm: "Algo".to_string(),
                test_name: "Fail".to_string(),
                message: "Expected failure".to_string(),
            })
        });
        runner.run_test("Pass2", "Algo", || Ok(()));

        let summary = runner.finish();
        assert_eq!(summary.total, 3);
        assert_eq!(summary.passed, 2);
        assert_eq!(summary.failed, 1);
        assert!(!summary.all_passed());
    }

    #[test]
    fn test_summary_time_accumulation() {
        let mut summary = KatSummary::new();

        // Add results with known execution times
        summary.add_result(KatTestResult::passed("T1".to_string(), "A".to_string(), 1000)); // 1ms
        summary.add_result(KatTestResult::passed("T2".to_string(), "A".to_string(), 2000)); // 2ms
        summary.add_result(KatTestResult::passed("T3".to_string(), "A".to_string(), 3000)); // 3ms

        assert_eq!(summary.total_time_ms, 6); // 1 + 2 + 3 = 6ms
    }

    #[test]
    fn test_many_test_results() {
        let mut summary = KatSummary::new();

        // Add 100 results
        for i in 0..100 {
            if i % 10 == 0 {
                summary.add_result(KatTestResult::failed(
                    format!("Test-{}", i),
                    "Algo".to_string(),
                    "Error".to_string(),
                    100,
                ));
            } else {
                summary.add_result(KatTestResult::passed(
                    format!("Test-{}", i),
                    "Algo".to_string(),
                    100,
                ));
            }
        }

        assert_eq!(summary.total, 100);
        assert_eq!(summary.passed, 90);
        assert_eq!(summary.failed, 10);
        assert!((summary.pass_rate() - 90.0).abs() < 0.001);
    }
}

// ============================================================================
// Test Vector Count Validation
// ============================================================================

mod vector_count_tests {
    use super::*;

    #[test]
    fn test_aes_128_gcm_vector_count() {
        assert_eq!(aes_gcm_kat::AES_128_GCM_VECTORS.len(), 3, "Expected 3 AES-128-GCM vectors");
    }

    #[test]
    fn test_aes_256_gcm_vector_count() {
        assert_eq!(aes_gcm_kat::AES_256_GCM_VECTORS.len(), 3, "Expected 3 AES-256-GCM vectors");
    }

    #[test]
    fn test_sha256_vector_count() {
        assert_eq!(sha2_kat::SHA256_VECTORS.len(), 4, "Expected 4 SHA-256 vectors");
    }

    #[test]
    fn test_sha224_vector_count() {
        assert_eq!(sha2_kat::SHA224_VECTORS.len(), 2, "Expected 2 SHA-224 vectors");
    }

    #[test]
    fn test_sha384_vector_count() {
        assert_eq!(sha2_kat::SHA384_VECTORS.len(), 2, "Expected 2 SHA-384 vectors");
    }

    #[test]
    fn test_sha512_vector_count() {
        assert_eq!(sha2_kat::SHA512_VECTORS.len(), 2, "Expected 2 SHA-512 vectors");
    }

    #[test]
    fn test_sha512_224_vector_count() {
        assert_eq!(sha2_kat::SHA512_224_VECTORS.len(), 2, "Expected 2 SHA-512/224 vectors");
    }

    #[test]
    fn test_sha512_256_vector_count() {
        assert_eq!(sha2_kat::SHA512_256_VECTORS.len(), 2, "Expected 2 SHA-512/256 vectors");
    }

    #[test]
    fn test_hkdf_sha256_vector_count() {
        assert_eq!(hkdf_kat::HKDF_SHA256_VECTORS.len(), 3, "Expected 3 HKDF-SHA256 vectors");
    }

    #[test]
    fn test_hmac_vector_count() {
        assert_eq!(hmac_kat::HMAC_VECTORS.len(), 6, "Expected 6 HMAC vectors");
    }

    #[test]
    fn test_chacha20_poly1305_vector_count() {
        assert_eq!(
            chacha20_poly1305_kat::CHACHA20_POLY1305_VECTORS.len(),
            1,
            "Expected 1 ChaCha20-Poly1305 vector"
        );
    }

    #[test]
    fn test_ml_kem_512_vector_count() {
        assert_eq!(ml_kem_kat::ML_KEM_512_VECTORS.len(), 2, "Expected 2 ML-KEM-512 vectors");
    }

    #[test]
    fn test_ml_kem_768_vector_count() {
        assert_eq!(ml_kem_kat::ML_KEM_768_VECTORS.len(), 2, "Expected 2 ML-KEM-768 vectors");
    }

    #[test]
    fn test_ml_kem_1024_vector_count() {
        assert_eq!(ml_kem_kat::ML_KEM_1024_VECTORS.len(), 2, "Expected 2 ML-KEM-1024 vectors");
    }

    #[test]
    fn test_ml_dsa_44_vector_count() {
        assert_eq!(ml_dsa_kat::ML_DSA_44_VECTORS.len(), 2, "Expected 2 ML-DSA-44 vectors");
    }

    #[test]
    fn test_ml_dsa_65_vector_count() {
        assert_eq!(ml_dsa_kat::ML_DSA_65_VECTORS.len(), 2, "Expected 2 ML-DSA-65 vectors");
    }

    #[test]
    fn test_ml_dsa_87_vector_count() {
        assert_eq!(ml_dsa_kat::ML_DSA_87_VECTORS.len(), 2, "Expected 2 ML-DSA-87 vectors");
    }
}
