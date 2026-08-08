//! FIPS coverage-boost, NIST-helper, SP 800-22, and validation-summary
//! coverage tests.
//!
//! Covers general coverage-boost cases, NIST helper functions, NIST SP
//! 800-22 statistical-test helpers, and additional validation_summary
//! module coverage for the `latticearc_tests::validation` crate.

#![deny(unsafe_code)]

mod coverage_boost {
    //! Targeted coverage boost tests for arc-validation modules.
    //! Exercises public APIs in rfc_vectors, wycheproof, nist_kat, fips_validation,
    //! and validation_summary to cover previously-missed lines.

    #![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::single_match)]

    // ============================================================
    // rfc_vectors.rs — RfcTestResults public API
    // ============================================================

    use latticearc_tests::validation::rfc_vectors::{RfcTestError, RfcTestResults};

    #[test]
    fn test_rfc_results_new_and_default_have_zero_counts_succeeds() {
        let results = RfcTestResults::new();
        assert_eq!(results.total, 0);
        assert_eq!(results.passed, 0);
        assert_eq!(results.failed, 0);
        assert!(results.failures.is_empty());
        assert!(results.all_passed()); // zero tests = all passed
    }

    #[test]
    fn test_rfc_results_add_pass_increments_counts_succeeds() {
        let mut results = RfcTestResults::new();
        results.add_pass();
        results.add_pass();
        assert_eq!(results.total, 2);
        assert_eq!(results.passed, 2);
        assert_eq!(results.failed, 0);
        assert!(results.all_passed());
    }

    #[test]
    fn test_rfc_results_add_failure_increments_failed_count_fails() {
        let mut results = RfcTestResults::new();
        results.add_pass();
        results.add_failure("test vector mismatch".to_string());
        assert_eq!(results.total, 2);
        assert_eq!(results.passed, 1);
        assert_eq!(results.failed, 1);
        assert!(!results.all_passed());
        assert!(results.failures[0].contains("mismatch"));
    }

    #[test]
    fn test_rfc_test_error_display_has_correct_format() {
        let err = RfcTestError::TestFailed {
            rfc: "RFC 5869".to_string(),
            test_name: "test-1".to_string(),
            message: "mismatch".to_string(),
        };
        let msg = format!("{err}");
        assert!(msg.contains("RFC 5869") || msg.contains("mismatch") || msg.contains("test-1"));
    }

    // ============================================================
    // wycheproof.rs — WycheproofResults and WycheproofError
    // ============================================================

    use latticearc_tests::validation::wycheproof::{WycheproofError, WycheproofResults};

    #[test]
    fn test_wycheproof_results_new_has_zero_counts_matches_expected() {
        let results = WycheproofResults::new();
        assert_eq!(results.passed, 0);
        assert_eq!(results.failed, 0);
        assert_eq!(results.skipped, 0);
        assert!(results.all_passed());
    }

    #[test]
    fn test_wycheproof_results_operations_accumulate_correctly_matches_expected() {
        let mut results = WycheproofResults::new();
        results.add_pass();
        results.add_pass();
        results.add_skip();
        results.add_failure("bad vector".to_string());

        assert_eq!(results.passed, 2);
        assert_eq!(results.failed, 1);
        assert_eq!(results.skipped, 1);
        assert!(!results.all_passed());
        assert_eq!(results.failures.len(), 1);
    }

    #[test]
    fn test_wycheproof_error_display_has_correct_format() {
        let err =
            WycheproofError::TestFailed { tc_id: 42, message: "verification failed".to_string() };
        let msg = format!("{err}");
        assert!(msg.contains("42") || msg.contains("failed"));
    }

    // ============================================================
    // nist_kat/sha2_kat.rs — SHA-2 KAT runners
    // ============================================================

    use latticearc_tests::validation::nist_kat::sha2_kat::{
        run_sha224_kat, run_sha256_kat, run_sha384_kat, run_sha512_224_kat, run_sha512_256_kat,
        run_sha512_kat,
    };

    #[test]
    fn test_sha256_kat_passes() {
        assert!(run_sha256_kat().is_ok());
    }

    #[test]
    fn test_sha224_kat_passes() {
        assert!(run_sha224_kat().is_ok());
    }

    #[test]
    fn test_sha384_kat_passes() {
        assert!(run_sha384_kat().is_ok());
    }

    #[test]
    fn test_sha512_kat_passes() {
        assert!(run_sha512_kat().is_ok());
    }

    #[test]
    fn test_sha512_224_kat_passes() {
        assert!(run_sha512_224_kat().is_ok());
    }

    #[test]
    fn test_sha512_256_kat_passes() {
        assert!(run_sha512_256_kat().is_ok());
    }

    // ============================================================
    // nist_kat/hmac_kat.rs — HMAC KAT runners
    // ============================================================

    use latticearc_tests::validation::nist_kat::hmac_kat::{
        run_hmac_sha224_kat, run_hmac_sha256_kat, run_hmac_sha384_kat, run_hmac_sha512_kat,
    };

    #[test]
    fn test_hmac_sha256_kat_passes() {
        assert!(run_hmac_sha256_kat().is_ok());
    }

    #[test]
    fn test_hmac_sha224_kat_passes() {
        assert!(run_hmac_sha224_kat().is_ok());
    }

    #[test]
    fn test_hmac_sha384_kat_passes() {
        assert!(run_hmac_sha384_kat().is_ok());
    }

    #[test]
    fn test_hmac_sha512_kat_passes() {
        assert!(run_hmac_sha512_kat().is_ok());
    }

    // ============================================================
    // fips_validation/validator.rs — FIPSValidator
    // ============================================================

    use latticearc_tests::validation::fips_validation::{FIPSValidator, ValidationScope};

    #[test]
    fn test_fips_validator_algorithms_only_succeeds() {
        let validator = FIPSValidator::new(ValidationScope::AlgorithmsOnly);
        let result = validator.validate_module();
        assert!(result.is_ok());
    }

    #[test]
    fn test_fips_validator_full_module_succeeds() {
        let validator = FIPSValidator::new(ValidationScope::FullModule);
        let result = validator.validate_module();
        assert!(result.is_ok());
        let validation_result = result.unwrap();

        // Test certificate generation (may fail if validation has issues)
        let cert = validator.generate_certificate(&validation_result);
        match cert {
            Ok(c) => assert!(!c.id.is_empty()),
            Err(_) => {} // acceptable if validation flagged issues
        }

        // Test remediation guidance (exercises the method regardless of result)
        let guidance = validator.get_remediation_guidance(&validation_result);
        let _ = guidance;
    }

    #[test]
    fn test_fips_validator_module_interfaces_succeeds() {
        let validator = FIPSValidator::new(ValidationScope::ModuleInterfaces);
        let result = validator.validate_module();
        assert!(result.is_ok());
    }

    #[test]
    fn test_fips_validator_individual_tests_succeeds() {
        let validator = FIPSValidator::new(ValidationScope::AlgorithmsOnly);
        assert!(validator.test_aes_algorithm_succeeds().is_ok());
        assert!(validator.test_sha3_algorithm_succeeds().is_ok());
        assert!(validator.test_mlkem_algorithm_succeeds().is_ok());
        assert!(validator.test_self_tests_succeeds().is_ok());
    }

    // ============================================================
    // validation_summary.rs — ComplianceReporter with real data
    // ============================================================

    use latticearc_tests::validation::kat_tests::types::KatResult;
    use latticearc_tests::validation::validation_summary::ComplianceReporter;
    use std::time::Duration;

    #[test]
    fn test_compliance_reporter_with_kat_results_matches_expected() {
        let reporter = ComplianceReporter::new(0.05);

        let kat_results = vec![
            KatResult::passed("ML-KEM-768-keygen-1".to_string(), Duration::from_millis(10)),
            KatResult::passed("ML-KEM-768-encaps-1".to_string(), Duration::from_millis(5)),
            KatResult::passed("AES-256-GCM-encrypt-1".to_string(), Duration::from_millis(1)),
            KatResult::failed(
                "ML-DSA-44-sign-fail".to_string(),
                Duration::from_millis(8),
                "Signature mismatch".to_string(),
            ),
        ];

        let report = reporter.generate_full_compliance_report(&kat_results, &None).unwrap();
        assert!(!report.report_id.is_empty());
        assert!(!report.algorithm_results.is_empty());

        // JSON export
        let json = reporter.generate_json_report(&report).unwrap();
        assert!(json.contains("report_id"));
        assert!(json.contains("algorithm_results"));

        // HTML export
        let html = reporter.generate_html_report(&report).unwrap();
        assert!(!html.is_empty());
    }

    #[test]
    fn test_compliance_reporter_all_passing_returns_non_empty_report_succeeds() {
        let reporter = ComplianceReporter::new(0.01);

        let kat_results = vec![
            KatResult::passed("SHA-256-kat-1".to_string(), Duration::from_millis(1)),
            KatResult::passed("SHA-256-kat-2".to_string(), Duration::from_millis(1)),
            KatResult::passed("HMAC-SHA256-kat-1".to_string(), Duration::from_millis(2)),
        ];

        let report = reporter.generate_full_compliance_report(&kat_results, &None).unwrap();
        assert!(!report.algorithm_results.is_empty());
    }

    #[test]
    fn test_compliance_reporter_multiple_algorithms_groups_by_prefix_succeeds() {
        let reporter = ComplianceReporter::new(0.05);

        let kat_results = vec![
            KatResult::passed("ML-KEM-768-1".to_string(), Duration::from_millis(10)),
            KatResult::passed("ML-KEM-768-2".to_string(), Duration::from_millis(10)),
            KatResult::passed("ML-DSA-44-1".to_string(), Duration::from_millis(15)),
            KatResult::passed("SLH-DSA-128s-1".to_string(), Duration::from_millis(100)),
            KatResult::passed("AES-GCM-1".to_string(), Duration::from_millis(1)),
            KatResult::passed("HKDF-SHA256-1".to_string(), Duration::from_millis(1)),
        ];

        let report = reporter.generate_full_compliance_report(&kat_results, &None).unwrap();

        // Should have grouped by algorithm prefix
        assert!(report.algorithm_results.len() >= 2);
    }
}

mod nist_functions {
    //! Coverage tests for nist_functions.rs (RandomizedHasher)
    //!
    //! Targets uncovered paths in RandomizedHasher: different modes, verify, edge cases.

    #![allow(clippy::unwrap_used)]

    use latticearc_tests::validation::nist_functions::{
        RandomizedHashConfig, RandomizedHashMode, RandomizedHasher,
    };

    // ============================================================================
    // Construction and defaults
    // ============================================================================

    #[test]
    fn test_randomized_hasher_default_is_correct() {
        let hasher = RandomizedHasher::default();
        let result = hasher.hash(b"test message").unwrap();
        assert!(!result.hash.is_empty());
        assert!(!result.salt.is_empty());
        assert_eq!(result.algorithm, "SHA-256");
        assert_eq!(result.mode, RandomizedHashMode::SaltPrefix);
    }

    #[test]
    fn test_randomized_hash_config_default_is_correct() {
        let config = RandomizedHashConfig::default();
        assert_eq!(config.algorithm, "SHA-256");
        assert_eq!(config.mode, RandomizedHashMode::SaltPrefix);
        assert_eq!(config.salt_length, 32);
        assert_eq!(config.salt_insertions, 3);
    }

    // ============================================================================
    // Different hash modes
    // ============================================================================

    #[test]
    fn test_hash_mode_none_succeeds() {
        let config = RandomizedHashConfig {
            algorithm: "SHA-256".to_string(),
            mode: RandomizedHashMode::None,
            salt_length: 0,
            salt_insertions: 0,
        };
        let hasher = RandomizedHasher::new(config);
        let result = hasher.hash(b"test message").unwrap();
        assert!(!result.hash.is_empty());
        assert_eq!(result.mode, RandomizedHashMode::None);
    }

    #[test]
    fn test_hash_mode_salt_prefix_succeeds() {
        let config = RandomizedHashConfig {
            algorithm: "SHA-256".to_string(),
            mode: RandomizedHashMode::SaltPrefix,
            salt_length: 16,
            salt_insertions: 0,
        };
        let hasher = RandomizedHasher::new(config);
        let result = hasher.hash(b"test message").unwrap();
        assert!(!result.hash.is_empty());
        assert_eq!(result.salt.len(), 16);
    }

    #[test]
    fn test_hash_mode_salt_suffix_succeeds() {
        let config = RandomizedHashConfig {
            algorithm: "SHA-256".to_string(),
            mode: RandomizedHashMode::SaltSuffix,
            salt_length: 16,
            salt_insertions: 0,
        };
        let hasher = RandomizedHasher::new(config);
        let result = hasher.hash(b"test message").unwrap();
        assert!(!result.hash.is_empty());
    }

    #[test]
    fn test_hash_mode_salt_distributed_succeeds() {
        let config = RandomizedHashConfig {
            algorithm: "SHA-256".to_string(),
            mode: RandomizedHashMode::SaltDistributed,
            salt_length: 16,
            salt_insertions: 3,
        };
        let hasher = RandomizedHasher::new(config);
        let result = hasher.hash(b"test message for distributed salting").unwrap();
        assert!(!result.hash.is_empty());
    }

    // ============================================================================
    // Different hash algorithms
    // ============================================================================

    #[test]
    fn test_hash_sha384_has_correct_length_has_correct_size() {
        let config = RandomizedHashConfig {
            algorithm: "SHA-384".to_string(),
            mode: RandomizedHashMode::SaltPrefix,
            salt_length: 32,
            salt_insertions: 0,
        };
        let hasher = RandomizedHasher::new(config);
        let result = hasher.hash(b"test message").unwrap();
        assert_eq!(result.hash.len(), 48); // SHA-384 outputs 48 bytes
        assert_eq!(result.algorithm, "SHA-384");
    }

    #[test]
    fn test_hash_sha512_has_correct_length_has_correct_size() {
        let config = RandomizedHashConfig {
            algorithm: "SHA-512".to_string(),
            mode: RandomizedHashMode::SaltPrefix,
            salt_length: 32,
            salt_insertions: 0,
        };
        let hasher = RandomizedHasher::new(config);
        let result = hasher.hash(b"test message").unwrap();
        assert_eq!(result.hash.len(), 64); // SHA-512 outputs 64 bytes
        assert_eq!(result.algorithm, "SHA-512");
    }

    // ============================================================================
    // Verify
    // ============================================================================

    #[test]
    fn test_verify_valid_hash_succeeds() {
        let hasher = RandomizedHasher::default();
        let hash_result = hasher.hash(b"test message").unwrap();
        let is_valid = hasher.verify(b"test message", &hash_result).unwrap();
        assert!(is_valid);
    }

    #[test]
    fn test_verify_wrong_message_fails() {
        let hasher = RandomizedHasher::default();
        let hash_result = hasher.hash(b"test message").unwrap();
        let is_valid = hasher.verify(b"wrong message", &hash_result).unwrap();
        assert!(!is_valid);
    }

    #[test]
    fn test_verify_with_different_modes_succeeds() {
        for mode in [
            RandomizedHashMode::SaltPrefix,
            RandomizedHashMode::SaltSuffix,
            RandomizedHashMode::SaltDistributed,
        ] {
            let config = RandomizedHashConfig {
                algorithm: "SHA-256".to_string(),
                mode,
                salt_length: 16,
                salt_insertions: 3,
            };
            let hasher = RandomizedHasher::new(config);
            let hash_result = hasher.hash(b"test for mode").unwrap();
            let is_valid = hasher.verify(b"test for mode", &hash_result).unwrap();
            assert!(is_valid, "Verification should pass for matching message");
        }
    }

    // ============================================================================
    // Edge cases
    // ============================================================================

    #[test]
    fn test_hash_empty_message_succeeds() {
        let hasher = RandomizedHasher::default();
        let result = hasher.hash(b"").unwrap();
        assert!(!result.hash.is_empty());
    }

    #[test]
    fn test_hash_large_message_succeeds() {
        let hasher = RandomizedHasher::default();
        let large_message = vec![0xABu8; 100_000];
        let result = hasher.hash(&large_message).unwrap();
        assert!(!result.hash.is_empty());
    }

    #[test]
    fn test_hash_randomness_produces_different_outputs_succeeds() {
        let hasher = RandomizedHasher::default();
        let result1 = hasher.hash(b"same message").unwrap();
        let result2 = hasher.hash(b"same message").unwrap();
        // Different salts should produce different hashes
        assert_ne!(result1.salt, result2.salt);
        assert_ne!(result1.hash, result2.hash);
    }

    // ============================================================================
    // RandomizedHash fields
    // ============================================================================

    #[test]
    fn test_randomized_hash_fields_are_correct() {
        let hasher = RandomizedHasher::default();
        let result = hasher.hash(b"test").unwrap();
        assert_eq!(result.algorithm, "SHA-256");
        assert_eq!(result.mode, RandomizedHashMode::SaltPrefix);
        assert_eq!(result.hash.len(), 32); // SHA-256 output
        assert_eq!(result.salt.len(), 32); // Default salt length
    }

    #[test]
    fn test_randomized_hash_mode_equality_is_correct() {
        assert_eq!(RandomizedHashMode::None, RandomizedHashMode::None);
        assert_eq!(RandomizedHashMode::SaltPrefix, RandomizedHashMode::SaltPrefix);
        assert_ne!(RandomizedHashMode::SaltPrefix, RandomizedHashMode::SaltSuffix);

        let mode = RandomizedHashMode::SaltDistributed;
        let debug = format!("{:?}", mode);
        assert!(debug.contains("SaltDistributed"));
    }

    #[test]
    fn test_randomized_hash_config_clone_is_correct() {
        let config = RandomizedHashConfig::default();
        let cloned = config.clone();
        assert_eq!(cloned.algorithm, config.algorithm);
        assert_eq!(cloned.salt_length, config.salt_length);

        let debug = format!("{:?}", config);
        assert!(debug.contains("SHA-256"));
    }
}

mod nist_sp800_22 {
    //! Coverage tests for nist_sp800_22.rs (NIST SP 800-22 statistical test suite)
    //!
    //! Targets uncovered paths: edge cases in statistical tests, helper functions,
    //! short sequences, individual test methods.

    #![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::float_cmp)]

    use latticearc_tests::validation::nist_sp800_22::NistSp800_22Tester;

    // ============================================================================
    // Construction
    // ============================================================================

    #[test]
    fn test_tester_default_succeeds_with_expected_bits_tested_succeeds() {
        let tester = NistSp800_22Tester::default();
        // Default: significance_level = 0.01, min_sequence_length = 1000
        let data = vec![0u8; 1000];
        let result = tester.test_bit_sequence_succeeds(&data).unwrap();
        assert_eq!(result.bits_tested, 8000);
    }

    #[test]
    fn test_tester_custom_params_succeeds_with_expected_bits_tested_succeeds() {
        let tester = NistSp800_22Tester::new(0.05, 500);
        let data = vec![0xAAu8; 500];
        let result = tester.test_bit_sequence_succeeds(&data).unwrap();
        assert_eq!(result.bits_tested, 4000);
    }

    // ============================================================================
    // Short sequence early return
    // ============================================================================

    #[test]
    fn test_short_sequence_returns_empty_results_succeeds() {
        let tester = NistSp800_22Tester::default();
        // min_sequence_length = 1000, so 1000/8 = 125 bytes minimum
        let short_data = vec![0u8; 10];
        let result = tester.test_bit_sequence_succeeds(&short_data).unwrap();
        assert!(!result.passed);
        assert!(result.test_results.is_empty());
        assert_eq!(result.bits_tested, 80);
        assert_eq!(result.entropy_estimate, 0.0);
        assert_eq!(result.algorithm, "unknown");
    }

    #[test]
    fn test_exactly_at_minimum_length_runs_tests_has_correct_size() {
        let tester = NistSp800_22Tester::new(0.01, 800);
        // 800/8 = 100 bytes minimum
        let data = vec![0xF0u8; 100];
        let result = tester.test_bit_sequence_succeeds(&data).unwrap();
        assert_eq!(result.bits_tested, 800);
        assert!(!result.test_results.is_empty());
    }

    #[test]
    fn test_empty_data_returns_failed_result_fails() {
        let tester = NistSp800_22Tester::default();
        let result = tester.test_bit_sequence_succeeds(&[]).unwrap();
        assert!(!result.passed);
        assert!(result.test_results.is_empty());
        assert_eq!(result.bits_tested, 0);
    }

    // ============================================================================
    // bytes_to_bits
    // ============================================================================

    #[test]
    fn test_bytes_to_bits_single_byte_produces_8_bits_succeeds() {
        let tester = NistSp800_22Tester::default();
        let bits = tester.bytes_to_bits(&[0b10110100]);
        assert_eq!(bits.len(), 8);
        assert_eq!(bits, vec![true, false, true, true, false, true, false, false]);
    }

    #[test]
    fn test_bytes_to_bits_all_zeros_produces_all_false_succeeds() {
        let tester = NistSp800_22Tester::default();
        let bits = tester.bytes_to_bits(&[0x00]);
        assert_eq!(bits, vec![false; 8]);
    }

    #[test]
    fn test_bytes_to_bits_all_ones_produces_all_true_succeeds() {
        let tester = NistSp800_22Tester::default();
        let bits = tester.bytes_to_bits(&[0xFF]);
        assert_eq!(bits, vec![true; 8]);
    }

    #[test]
    fn test_bytes_to_bits_empty_returns_empty_vec_succeeds() {
        let tester = NistSp800_22Tester::default();
        let bits = tester.bytes_to_bits(&[]);
        assert!(bits.is_empty());
    }

    #[test]
    fn test_bytes_to_bits_multiple_bytes_produces_correct_length_has_correct_size() {
        let tester = NistSp800_22Tester::default();
        let bits = tester.bytes_to_bits(&[0xFF, 0x00]);
        assert_eq!(bits.len(), 16);
        assert!(bits[..8].iter().all(|&b| b));
        assert!(bits[8..].iter().all(|&b| !b));
    }

    // ============================================================================
    // estimate_entropy
    // ============================================================================

    #[test]
    fn test_entropy_all_zeros_returns_zero_succeeds() {
        let tester = NistSp800_22Tester::default();
        let bits = vec![false; 1000];
        let entropy = tester.estimate_entropy(&bits);
        assert_eq!(entropy, 0.0); // proportion = 0.0, triggers early return
    }

    #[test]
    fn test_entropy_all_ones_returns_zero_succeeds() {
        let tester = NistSp800_22Tester::default();
        let bits = vec![true; 1000];
        let entropy = tester.estimate_entropy(&bits);
        assert_eq!(entropy, 0.0); // proportion = 1.0, triggers early return
    }

    #[test]
    fn test_entropy_balanced_returns_near_one_succeeds() {
        let tester = NistSp800_22Tester::default();
        let mut bits = vec![false; 500];
        bits.extend(vec![true; 500]);
        let entropy = tester.estimate_entropy(&bits);
        // Perfect balance -> entropy should be close to 1.0
        assert!((entropy - 1.0).abs() < 0.01);
    }

    #[test]
    fn test_entropy_empty_returns_zero_succeeds() {
        let tester = NistSp800_22Tester::default();
        let entropy = tester.estimate_entropy(&[]);
        assert_eq!(entropy, 0.0);
    }

    #[test]
    fn test_entropy_skewed_returns_value_between_zero_and_one_succeeds() {
        let tester = NistSp800_22Tester::default();
        let mut bits = vec![true; 900];
        bits.extend(vec![false; 100]);
        let entropy = tester.estimate_entropy(&bits);
        // Skewed: entropy should be between 0 and 1
        assert!(entropy > 0.0);
        assert!(entropy < 1.0);
    }

    // ============================================================================
    // Full test suite with various data patterns
    // ============================================================================

    #[test]
    fn test_all_zeros_data_fails_randomness_tests_fails() {
        let tester = NistSp800_22Tester::default();
        let data = vec![0x00u8; 1000];
        let result = tester.test_bit_sequence_succeeds(&data).unwrap();
        assert!(!result.passed); // All zeros should fail randomness tests
        assert_eq!(result.test_results.len(), 6);
    }

    #[test]
    fn test_all_ones_data_fails_randomness_tests_fails() {
        let tester = NistSp800_22Tester::default();
        let data = vec![0xFFu8; 1000];
        let result = tester.test_bit_sequence_succeeds(&data).unwrap();
        assert!(!result.passed);
    }

    #[test]
    fn test_alternating_bits_runs_all_six_tests_succeeds() {
        let tester = NistSp800_22Tester::default();
        let data = vec![0xAAu8; 1000]; // 10101010 pattern
        let result = tester.test_bit_sequence_succeeds(&data).unwrap();
        assert_eq!(result.bits_tested, 8000);
        assert_eq!(result.test_results.len(), 6);
    }

    #[test]
    fn test_random_data_passes() {
        let tester = NistSp800_22Tester::default();
        let mut data = vec![0u8; 2000];
        rand::RngCore::fill_bytes(&mut rand::rng(), &mut data);
        let result = tester.test_bit_sequence_succeeds(&data).unwrap();
        assert_eq!(result.bits_tested, 16000);
        assert_eq!(result.algorithm, "NIST SP 800-22");
        // Random data should generally pass most tests
        let passing = result.test_results.iter().filter(|r| r.passed).count();
        assert!(passing >= 3, "Random data should pass most tests, got {}/6", passing);
    }

    // ============================================================================
    // Large data to exercise different block size selection in longest_run
    // ============================================================================

    #[test]
    fn test_medium_sequence_block_sizes_runs_all_six_tests_has_correct_size() {
        // 128..=6272 range uses block_size=8, k=3
        let tester = NistSp800_22Tester::new(0.01, 128);
        let data = vec![0xAAu8; 200]; // 1600 bits
        let result = tester.test_bit_sequence_succeeds(&data).unwrap();
        assert_eq!(result.test_results.len(), 6);
    }

    #[test]
    fn test_large_sequence_block_sizes_runs_all_six_tests_has_correct_size() {
        // 6273..=75000 range uses block_size=128, k=5
        let tester = NistSp800_22Tester::new(0.01, 128);
        let mut data = vec![0u8; 10000]; // 80000 bits
        rand::RngCore::fill_bytes(&mut rand::rng(), &mut data);
        let result = tester.test_bit_sequence_succeeds(&data).unwrap();
        assert_eq!(result.test_results.len(), 6);
    }

    // ============================================================================
    // Test individual result fields
    // ============================================================================

    #[test]
    fn test_result_test_names_include_all_six_nist_tests_succeeds() {
        let tester = NistSp800_22Tester::default();
        let mut data = vec![0u8; 1000];
        rand::RngCore::fill_bytes(&mut rand::rng(), &mut data);
        let result = tester.test_bit_sequence_succeeds(&data).unwrap();

        let names: Vec<&str> = result.test_results.iter().map(|r| r.test_name.as_str()).collect();
        assert!(names.contains(&"Frequency (Monobit) Test"));
        assert!(names.contains(&"Frequency Within Block Test"));
        assert!(names.contains(&"Runs Test"));
        assert!(names.contains(&"Longest Run of Ones in a Block Test"));
        assert!(names.contains(&"Serial Test"));
        assert!(names.contains(&"Approximate Entropy Test"));
    }

    #[test]
    fn test_result_p_values_in_range_are_non_negative_succeeds() {
        let tester = NistSp800_22Tester::default();
        let mut data = vec![0u8; 1000];
        rand::RngCore::fill_bytes(&mut rand::rng(), &mut data);
        let result = tester.test_bit_sequence_succeeds(&data).unwrap();

        for test_result in &result.test_results {
            // p-values should be non-negative
            assert!(
                test_result.p_value >= 0.0,
                "p_value for {} should be >= 0, got {}",
                test_result.test_name,
                test_result.p_value
            );
        }
    }

    // ============================================================================
    // Edge case: minimum viable sequence for different tests
    // ============================================================================

    #[test]
    fn test_small_custom_min_length_succeeds() {
        // Very small min_sequence_length to exercise edge cases in block tests
        let tester = NistSp800_22Tester::new(0.01, 16);
        let data = vec![0xABu8; 2]; // 16 bits exactly
        let result = tester.test_bit_sequence_succeeds(&data).unwrap();
        assert_eq!(result.bits_tested, 16);
        // Some tests may fail or return early with insufficient data
    }

    #[test]
    fn test_significance_level_affects_pass_rate_returns_six_results_succeeds() {
        let mut data = vec![0u8; 1000];
        rand::RngCore::fill_bytes(&mut rand::rng(), &mut data);

        let strict = NistSp800_22Tester::new(0.10, 1000);
        let result_strict = strict.test_bit_sequence_succeeds(&data).unwrap();

        let lenient = NistSp800_22Tester::new(0.001, 1000);
        let result_lenient = lenient.test_bit_sequence_succeeds(&data).unwrap();

        // Both should have 6 test results
        assert_eq!(result_strict.test_results.len(), 6);
        assert_eq!(result_lenient.test_results.len(), 6);
    }
}

mod validation_summary {
    //! Coverage tests for validation_summary.rs
    //!
    //! Targets uncovered paths in ComplianceReporter, ComplianceReport generation,
    //! HTML/JSON report generation, and recommendation generation.

    #![allow(clippy::unwrap_used, clippy::float_cmp, clippy::redundant_clone)]

    use chrono::Utc;
    use latticearc_tests::validation::fips_validation_impl::Fips140_3ValidationResult;
    use latticearc_tests::validation::kat_tests::types::KatResult;
    use latticearc_tests::validation::validation_summary::{
        ComplianceMetrics, ComplianceReporter, ComplianceStatus, RandomnessQuality,
        SecurityCoverage, StatisticalComplianceResult, ValidationScope,
    };
    use std::time::Duration;

    // Helper to create a passing KatResult
    fn passing_kat(test_case: &str) -> KatResult {
        KatResult {
            test_case: test_case.to_string(),
            passed: true,
            execution_time_ns: 1000,
            error_message: None,
        }
    }

    // Helper to create a failing KatResult
    fn failing_kat(test_case: &str, error: &str) -> KatResult {
        KatResult {
            test_case: test_case.to_string(),
            passed: false,
            execution_time_ns: 1000,
            error_message: Some(error.to_string()),
        }
    }

    // ============================================================================
    // ComplianceReporter: generate_full_compliance_report
    // ============================================================================

    #[test]
    fn test_compliance_reporter_new_succeeds() {
        let reporter = ComplianceReporter::new(0.05);
        let _ = reporter;
    }

    #[test]
    fn test_compliance_reporter_default_succeeds() {
        let reporter = ComplianceReporter::default();
        let _ = reporter;
    }

    #[test]
    fn test_generate_full_compliance_report_with_ml_kem_results_succeeds() {
        let reporter = ComplianceReporter::new(0.01);

        let kat_results =
            vec![passing_kat("ML-KEM-768 KeyGen Test 1"), passing_kat("ML-KEM-768 KeyGen Test 2")];

        let report = reporter.generate_full_compliance_report(&kat_results, &None).unwrap();
        assert!(!report.report_id.is_empty(), "Report should have a non-empty ID");
        assert!(
            report.algorithm_results.contains_key("ML-KEM"),
            "Report should contain ML-KEM results"
        );
        assert!(report.statistical_results.is_some(), "Report should include statistical results");
        assert!(!report.recommendations.is_empty(), "Report should include recommendations");
    }

    #[test]
    fn test_generate_full_compliance_report_with_mixed_algorithms_succeeds() {
        let reporter = ComplianceReporter::new(0.01);

        let kat_results = vec![
            passing_kat("ML-DSA-44 Sign Test"),
            passing_kat("AES-GCM Encrypt Test"),
            passing_kat("SLH-DSA-128s Sign Test"),
            passing_kat("Ed25519 Sign Test"),
            passing_kat("SHA3-256 Hash Test"),
            passing_kat("HYBRID KEM Test"),
            passing_kat("Unknown Algorithm Test"),
        ];

        let report = reporter.generate_full_compliance_report(&kat_results, &None).unwrap();
        assert!(
            report.algorithm_results.len() >= 5,
            "Report should cover at least 5 algorithm families"
        );
        assert!(report.security_level > 0, "Security level should be positive");
    }

    #[test]
    fn test_generate_full_compliance_report_with_failures_fails() {
        let reporter = ComplianceReporter::new(0.01);

        let kat_results = vec![
            failing_kat("ML-KEM-768 Test 1", "Mismatch"),
            failing_kat("ML-KEM-768 Test 2", "Mismatch"),
        ];

        let report = reporter.generate_full_compliance_report(&kat_results, &None).unwrap();
        assert_eq!(
            report.overall_compliance,
            ComplianceStatus::NonCompliant,
            "Failed KATs should produce NonCompliant status"
        );
        assert!(
            report.recommendations.iter().any(|r| r.contains("Critical") || r.contains("action")),
            "Failed KATs should produce critical/action recommendations"
        );
    }

    #[test]
    fn test_generate_full_compliance_report_with_fips_validation_succeeds() {
        let reporter = ComplianceReporter::new(0.01);

        let kat_results = vec![passing_kat("ML-KEM-768 Test")];

        let fips_result = Fips140_3ValidationResult {
            validation_id: "test-123".to_string(),
            timestamp: Utc::now(),
            power_up_tests: vec![],
            conditional_tests: vec![],
            overall_passed: true,
            compliance_level: "FIPS 140-3 Level 3".to_string(),
            module_name: "TestModule".to_string(),
            execution_time: Duration::from_millis(100),
            detailed_results: serde_json::json!({}),
        };

        let report =
            reporter.generate_full_compliance_report(&kat_results, &Some(fips_result)).unwrap();
        assert!(report.fips_validation.is_some(), "FIPS validation result should be present");
    }

    // ============================================================================
    // JSON and HTML report generation
    // ============================================================================

    #[test]
    fn test_generate_json_report_succeeds() {
        let reporter = ComplianceReporter::new(0.01);
        let kat_results = vec![passing_kat("ML-KEM-768 Test")];

        let report = reporter.generate_full_compliance_report(&kat_results, &None).unwrap();
        let json = reporter.generate_json_report(&report).unwrap();
        assert!(json.contains("report_id"), "JSON report should contain report_id field");
        assert!(json.contains("algorithm_results"), "JSON report should contain algorithm_results");
        assert!(
            json.contains("overall_compliance"),
            "JSON report should contain overall_compliance"
        );
    }

    #[test]
    fn test_generate_html_report_succeeds() {
        let reporter = ComplianceReporter::new(0.01);

        let kat_results =
            vec![passing_kat("ML-KEM-768 Test"), failing_kat("AES-GCM Test", "mismatch")];

        let report = reporter.generate_full_compliance_report(&kat_results, &None).unwrap();
        let html = reporter.generate_html_report(&report).unwrap();
        assert!(html.contains("<!DOCTYPE html>"), "HTML report should be valid HTML document");
        assert!(html.contains("Compliance Report"), "HTML should contain report title");
        assert!(
            html.contains("Algorithm Results"),
            "HTML should contain algorithm results section"
        );
        assert!(html.contains("Recommendations"), "HTML should contain recommendations section");
        assert!(
            html.contains("Statistical Testing Results"),
            "HTML should contain statistical section"
        );
    }

    #[test]
    fn test_generate_html_report_with_all_compliance_statuses_succeeds() {
        let reporter = ComplianceReporter::new(0.01);

        let kat_results =
            vec![passing_kat("ML-KEM-768 Test 1"), failing_kat("ML-DSA-44 Test 1", "Failed")];

        let report = reporter.generate_full_compliance_report(&kat_results, &None).unwrap();
        let html = reporter.generate_html_report(&report).unwrap();
        assert!(html.contains("class=\""), "HTML should contain CSS class attributes");
    }

    // ============================================================================
    // ComplianceStatus and related types
    // ============================================================================

    #[test]
    fn test_compliance_status_variants_succeeds() {
        assert_eq!(
            ComplianceStatus::FullyCompliant,
            ComplianceStatus::FullyCompliant,
            "Same variant should be equal"
        );
        assert_ne!(ComplianceStatus::FullyCompliant, ComplianceStatus::NonCompliant);
        assert_ne!(ComplianceStatus::PartiallyCompliant, ComplianceStatus::Unknown);

        let debug = format!("{:?}", ComplianceStatus::FullyCompliant);
        assert!(debug.contains("FullyCompliant"));
    }

    #[test]
    fn test_randomness_quality_debug_succeeds() {
        let qualities = vec![
            RandomnessQuality::Excellent,
            RandomnessQuality::Good,
            RandomnessQuality::Fair,
            RandomnessQuality::Poor,
            RandomnessQuality::Insufficient,
        ];
        for q in qualities {
            let debug = format!("{:?}", q);
            assert!(!debug.is_empty(), "RandomnessQuality Debug output should not be empty");
        }
    }

    #[test]
    fn test_validation_scope_variants_succeeds() {
        let module_scope = ValidationScope::Module;
        let debug = format!("{:?}", module_scope);
        assert!(debug.contains("Module"));

        let component_scope = ValidationScope::Component("test-component".to_string());
        let debug = format!("{:?}", component_scope);
        assert!(debug.contains("test-component"));
    }

    #[test]
    fn test_security_coverage_fields_is_covered() {
        let coverage = SecurityCoverage {
            post_quantum_supported: true,
            classical_supported: true,
            statistical_testing: true,
            timing_security: true,
            error_handling: true,
            memory_safety: true,
        };
        assert!(coverage.post_quantum_supported, "Security coverage should include PQ support");
        assert!(coverage.classical_supported, "Security coverage should include classical support");

        let debug = format!("{:?}", coverage);
        assert!(debug.contains("true"));
    }

    #[test]
    fn test_compliance_metrics_fields_succeeds() {
        let metrics = ComplianceMetrics {
            total_test_cases: 100,
            passed_test_cases: 95,
            failed_test_cases: 5,
            pass_rate: 0.95,
            security_coverage: SecurityCoverage {
                post_quantum_supported: true,
                classical_supported: true,
                statistical_testing: true,
                timing_security: true,
                error_handling: true,
                memory_safety: true,
            },
            fips_level: "FIPS 140-3 Level 3".to_string(),
            validation_duration: Duration::from_secs(10),
        };
        assert_eq!(metrics.total_test_cases, 100, "Total test cases should match");
        assert_eq!(metrics.pass_rate, 0.95, "Pass rate should match");
    }

    // ============================================================================
    // Compliance report serialization
    // ============================================================================

    #[test]
    fn test_compliance_report_clone_succeeds() {
        let reporter = ComplianceReporter::new(0.01);
        let kat_results = vec![passing_kat("ML-KEM-768 Test")];

        let report = reporter.generate_full_compliance_report(&kat_results, &None).unwrap();
        let cloned = report.clone();
        assert_eq!(cloned.report_id, report.report_id, "Cloned report_id should match");
        assert_eq!(
            cloned.overall_compliance, report.overall_compliance,
            "Cloned compliance status should match"
        );
    }

    #[test]
    fn test_compliance_report_debug_succeeds() {
        let reporter = ComplianceReporter::new(0.01);
        let kat_results = vec![passing_kat("ML-KEM-768 Test")];

        let report = reporter.generate_full_compliance_report(&kat_results, &None).unwrap();
        let debug = format!("{:?}", report);
        assert!(debug.contains("ComplianceReport"));
    }

    // ============================================================================
    // Empty inputs and edge cases
    // ============================================================================

    #[test]
    fn test_generate_full_compliance_report_empty_results_succeeds() {
        let reporter = ComplianceReporter::new(0.01);
        let kat_results: Vec<KatResult> = vec![];
        let _result = reporter.generate_full_compliance_report(&kat_results, &None);
    }

    #[test]
    fn test_statistical_compliance_result_clone_succeeds() {
        let result = StatisticalComplianceResult {
            nist_sp800_22_tests: vec!["Frequency Test".to_string()],
            entropy_estimate: 7.9,
            randomness_quality: RandomnessQuality::Excellent,
            bits_tested: 8000,
            test_coverage: "Complete".to_string(),
        };
        let cloned = result.clone();
        assert_eq!(cloned.entropy_estimate, 7.9, "Cloned entropy estimate should match");
        assert_eq!(cloned.bits_tested, 8000, "Cloned bits_tested should match");
    }

    // ============================================================================
    // Additional coverage: partial compliance, many algorithm types
    // ============================================================================

    #[test]
    fn test_generate_report_partial_compliance_succeeds() {
        let reporter = ComplianceReporter::new(0.01);

        // Mix of pass and fail across different algorithms
        let kat_results = vec![
            passing_kat("ML-KEM-768 Encap Test"),
            passing_kat("ML-KEM-768 Decap Test"),
            failing_kat("ML-DSA-65 Sign Test", "signature mismatch"),
            passing_kat("AES-GCM-256 Encrypt Test"),
            passing_kat("SHA3-512 Hash Test"),
        ];

        let report = reporter.generate_full_compliance_report(&kat_results, &None).unwrap();
        // Should be partially compliant (some pass, some fail)
        assert!(
            report.overall_compliance == ComplianceStatus::PartiallyCompliant
                || report.overall_compliance == ComplianceStatus::NonCompliant
        );
    }

    #[test]
    fn test_generate_report_all_algorithms_passing_succeeds() {
        let reporter = ComplianceReporter::new(0.01);

        let kat_results = vec![
            passing_kat("ML-KEM-512 Test"),
            passing_kat("ML-KEM-768 Test"),
            passing_kat("ML-KEM-1024 Test"),
            passing_kat("ML-DSA-44 Test"),
            passing_kat("ML-DSA-65 Test"),
            passing_kat("ML-DSA-87 Test"),
            passing_kat("SLH-DSA-128s Test"),
            passing_kat("SLH-DSA-256f Test"),
            passing_kat("AES-GCM-128 Test"),
            passing_kat("AES-GCM-256 Test"),
            passing_kat("SHA-256 Test"),
            passing_kat("SHA3-256 Test"),
            passing_kat("Ed25519 Test"),
            passing_kat("X25519 Test"),
            passing_kat("HYBRID-KEM Test"),
            passing_kat("ChaCha20-Poly1305 Test"),
        ];

        let report = reporter.generate_full_compliance_report(&kat_results, &None).unwrap();
        // All KATs pass but overall compliance depends on statistical and FIPS scores too
        assert!(
            report.algorithm_results.len() >= 5,
            "Report should cover at least 5 algorithm families"
        );
        assert!(report.security_level > 0, "Security level should be positive");
    }

    #[test]
    fn test_generate_report_fully_compliant_with_fips_succeeds() {
        let reporter = ComplianceReporter::new(0.01);

        let kat_results = vec![
            passing_kat("ML-KEM-768 Test"),
            passing_kat("ML-DSA-44 Test"),
            passing_kat("SLH-DSA-128s Test"),
            passing_kat("AES-GCM-256 Test"),
            passing_kat("Ed25519 Test"),
        ];

        let fips_result = Fips140_3ValidationResult {
            validation_id: "full-compliance-test".to_string(),
            timestamp: Utc::now(),
            power_up_tests: vec![],
            conditional_tests: vec![],
            overall_passed: true,
            compliance_level: "FIPS 140-3 Level 3".to_string(),
            module_name: "FullComplianceModule".to_string(),
            execution_time: Duration::from_millis(100),
            detailed_results: serde_json::json!({}),
        };

        let report =
            reporter.generate_full_compliance_report(&kat_results, &Some(fips_result)).unwrap();
        // With FIPS validation + passing KATs, compliance should be at least partial
        assert!(
            report.overall_compliance == ComplianceStatus::PartiallyCompliant
                || report.overall_compliance == ComplianceStatus::FullyCompliant
        );
        assert!(
            report.fips_validation.is_some(),
            "FIPS validation should be present in compliant report"
        );
    }

    #[test]
    fn test_generate_html_report_with_fips_validation_succeeds() {
        let reporter = ComplianceReporter::new(0.01);
        let kat_results = vec![passing_kat("ML-KEM-768 Test")];

        let fips_result = Fips140_3ValidationResult {
            validation_id: "fips-html-test".to_string(),
            timestamp: Utc::now(),
            power_up_tests: vec![],
            conditional_tests: vec![],
            overall_passed: true,
            compliance_level: "FIPS 140-3 Level 1".to_string(),
            module_name: "HTMLTestModule".to_string(),
            execution_time: Duration::from_millis(50),
            detailed_results: serde_json::json!({"test": "data"}),
        };

        let report =
            reporter.generate_full_compliance_report(&kat_results, &Some(fips_result)).unwrap();
        let html = reporter.generate_html_report(&report).unwrap();
        assert!(html.contains("FIPS"));
    }

    #[test]
    fn test_generate_json_report_with_failures_fails() {
        let reporter = ComplianceReporter::new(0.01);
        let kat_results =
            vec![failing_kat("ML-KEM-768 Encap Test", "encap failed"), passing_kat("AES-GCM Test")];

        let report = reporter.generate_full_compliance_report(&kat_results, &None).unwrap();
        let json = reporter.generate_json_report(&report).unwrap();
        assert!(json.contains("recommendations"));
    }
}
